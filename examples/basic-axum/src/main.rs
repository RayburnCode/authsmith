//! # basic-axum — AuthSmith Full-Stack Example
//!
//! A real, runnable Axum HTTP server demonstrating every AuthSmith crate
//! working together in a cohesive application:
//!
//! | Crate                       | Role in this example                                  |
//! |-----------------------------|-------------------------------------------------------|
//! | `authsmith-core`            | `AuthEngine`, `AuthUser`, `Session`, all core traits  |
//! | `authsmith-core` (`session`)| `SecureTokenGenerator` — CSPRNG 256-bit tokens        |
//! | `authsmith-password`        | `Argon2Hasher` — Argon2id password hashing + policy   |
//! | `authsmith-axum`            | `auth_middleware`, `AuthSession`, `require_role`      |
//! | `authsmith-notify` (`smtp`) | `EmailPlugin` + mock sender (prints to stdout)        |
//! | `authsmith-notify` (`webhook`) | `WebhookPlugin` + noop sender (prints to stdout)   |
//!
//! ## Run
//!
//! ```sh
//! cargo run -p basic-axum
//! ```
//!
//! ## Try the API (second terminal)
//!
//! ```sh
//! # Register a realtor
//! curl -s -X POST http://localhost:3000/register \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"alice@example.com","password":"correct-horse-battery","role":"realtor","license_number":"CA-DRE-01234567"}' | jq
//!
//! # Login — capture the session token
//! TOKEN=$(curl -s -X POST http://localhost:3000/login \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"alice@example.com","password":"correct-horse-battery"}' | jq -r .token)
//!
//! # Authenticated profile
//! curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN" | jq
//!
//! # Admin panel — Alice is Realtor so this returns 403
//! curl -s http://localhost:3000/admin -H "Authorization: Bearer $TOKEN"
//!
//! # Rotate the session (get a fresh token)
//! TOKEN=$(curl -s -X POST http://localhost:3000/refresh \
//!   -H "Authorization: Bearer $TOKEN" | jq -r .token)
//!
//! # Logout — revoke the session
//! curl -s -X DELETE http://localhost:3000/logout -H "Authorization: Bearer $TOKEN"
//!
//! # /me now returns 401
//! curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
//! ```

use async_trait::async_trait;
use authsmith_axum::{auth_middleware, extract_token, require_role, AuthSession, SharedAuth};
use authsmith_core::{
    session::{now_secs, SecureTokenGenerator},
    AuthConfig, AuthEngine, AuthError, AuthProvider, AuthUser, CreateUserInput,
    PasswordHasher, Role, Session, SessionMeta, SessionProvider, TokenGenerator,
};
use authsmith_notify::email::{
    sender::EmailSender,
    template::{DefaultEmailTemplates, EmailMessage, EmailTemplates},
    EmailPlugin, EmailPluginConfig,
};
use authsmith_notify::webhook::{AuthWebhookPayload, WebhookPlugin};
use authsmith_password::Argon2Hasher;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use hooksmith_core::WebhookSender;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

// ── In-memory user store ──────────────────────────────────────────────────────
//
// In production, swap this for `authsmith_db::sqlite::SqliteUserStore` (or
// the Postgres variant). The engine is generic over `AuthProvider`, so the
// swap requires zero changes to the rest of this file.

struct MemUserStore {
    /// Stores (user, optional password hash) keyed by user ID.
    inner: Mutex<HashMap<String, (AuthUser, Option<String>)>>,
    id_gen: SecureTokenGenerator,
}

impl Default for MemUserStore {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            id_gen: SecureTokenGenerator::default(),
        }
    }
}

impl MemUserStore {
    /// Retrieve the stored Argon2 hash for a given email — used in the login handler.
    ///
    /// A real DB adapter would expose this via a dedicated query; for the
    /// in-memory store we read it directly.
    fn password_hash_for(&self, email: &str) -> Option<String> {
        self.inner
            .lock()
            .ok()?
            .values()
            .find(|(u, _)| u.email.as_deref() == Some(email))
            .and_then(|(_, h)| h.clone())
    }
}

#[derive(Debug, thiserror::Error)]
enum UserStoreError {
    #[error("email already registered")]
    DuplicateEmail,
    #[error("internal store error")]
    Poison,
}

#[async_trait]
impl AuthProvider for MemUserStore {
    type Error = UserStoreError;

    async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error> {
        let mut store = self.inner.lock().map_err(|_| UserStoreError::Poison)?;

        if let Some(email) = &input.email {
            if store.values().any(|(u, _)| u.email.as_deref() == Some(email)) {
                return Err(UserStoreError::DuplicateEmail);
            }
        }

        let now = now_secs();
        let user = AuthUser {
            id: self.id_gen.generate(),
            email: input.email,
            peer_id: input.peer_id,
            roles: input.roles,
            metadata: input.metadata,
            email_verified: false,
            created_at: now,
            updated_at: now,
        };
        store.insert(user.id.clone(), (user.clone(), input.password_hash));
        Ok(user)
    }

    async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| UserStoreError::Poison)?
            .get(id)
            .map(|(u, _)| u.clone()))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| UserStoreError::Poison)?
            .values()
            .find(|(u, _)| u.email.as_deref() == Some(email))
            .map(|(u, _)| u.clone()))
    }

    async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error> {
        let mut store = self.inner.lock().map_err(|_| UserStoreError::Poison)?;
        if let Some(entry) = store.get_mut(&user.id) {
            entry.0 = user.clone();
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
        self.inner
            .lock()
            .map_err(|_| UserStoreError::Poison)?
            .remove(id);
        Ok(())
    }
}

// ── In-memory session store ───────────────────────────────────────────────────

#[derive(Default)]
struct MemSessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    token_gen: SecureTokenGenerator,
}

#[derive(Debug, thiserror::Error)]
#[error("session store lock poisoned")]
struct SessionStoreError;

#[async_trait]
impl SessionProvider for MemSessionStore {
    type Error = SessionStoreError;

    async fn create_session(
        &self,
        user_id: &str,
        expires_at: i64,
        meta: SessionMeta,
    ) -> Result<Session, Self::Error> {
        // SecureTokenGenerator produces 256-bit CSPRNG base64url tokens.
        let session = Session {
            token: self.token_gen.generate(),
            user_id: user_id.to_string(),
            expires_at,
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            created_at: now_secs(),
        };
        self.sessions
            .lock()
            .map_err(|_| SessionStoreError)?
            .insert(session.token.clone(), session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| SessionStoreError)?
            .get(token)
            .cloned())
    }

    async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
        self.sessions
            .lock()
            .map_err(|_| SessionStoreError)?
            .remove(token);
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
        self.sessions
            .lock()
            .map_err(|_| SessionStoreError)?
            .retain(|_, s| s.user_id != user_id);
        Ok(())
    }
}

// ── Email sender: stdout mock (replaces lettre SMTP in this example) ──────────
//
// In production, swap `PrintEmailSender` for `SmtpEmailSender`:
//
//   use authsmith_notify::email::{SmtpConfig, SmtpEmailSender, TlsMode};
//   let sender = SmtpEmailSender::new(SmtpConfig {
//       host:     "smtp.sendgrid.net".into(),
//       port:     587,
//       username: "apikey".into(),
//       password: std::env::var("SENDGRID_API_KEY").unwrap(),
//       from:     "DSCR Express <noreply@dscrexpress.com>".into(),
//       tls:      TlsMode::StartTls,
//   })?;

struct PrintEmailSender;

#[async_trait]
impl EmailSender for PrintEmailSender {
    async fn send(
        &self,
        msg: EmailMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!(
            "\n╔═ [email] ══════════════════════════════════════\n\
             ║  To:      {}\n\
             ║  Subject: {}\n\
             ╟───────────────────────────────────────────────\n\
             ║  {}\n\
             ╚═══════════════════════════════════════════════\n",
            msg.to,
            msg.subject,
            msg.text
                .as_deref()
                .unwrap_or("[html-only]")
                .replace('\n', "\n║  "),
        );
        Ok(())
    }
}

// ── Webhook sender: stdout mock (replaces HTTP POST in this example) ──────────
//
// In production, swap `PrintWebhookSender` for `AuthWebhookSender`:
//
//   use authsmith_notify::webhook::AuthWebhookSender;
//   let sender = AuthWebhookSender::builder()
//       .endpoint("https://yourapp.com/webhooks/auth")
//       .build();

struct PrintWebhookSender;

// WebhookSender from hooksmith-core uses native async (no #[async_trait]).
impl WebhookSender for PrintWebhookSender {
    type Message = AuthWebhookPayload;
    type Error = std::convert::Infallible;

    async fn send(&self, msg: &AuthWebhookPayload) -> Result<(), std::convert::Infallible> {
        println!(
            "[webhook] event={:<20} timestamp={} data={}",
            msg.event,
            msg.timestamp,
            serde_json::to_string(&msg.data).unwrap_or_default(),
        );
        Ok(())
    }
}

// ── Application state ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    /// The central auth engine — shared across all request handlers.
    auth: SharedAuth<MemUserStore, MemSessionStore>,
    /// Argon2id hasher — a single instance is reused across all requests
    /// to avoid reallocating the memory-hard parameters.
    hasher: Arc<Argon2Hasher>,
    /// Kept in state for direct sends (email verification, password reset)
    /// that are triggered by route logic rather than plugin lifecycle hooks.
    email_sender: Arc<PrintEmailSender>,
    /// Stateless template renderer — shared across direct send calls.
    email_templates: Arc<DefaultEmailTemplates>,
}

/// `auth_middleware` extracts `State<SharedAuth<U, S>>` from the router.
/// `FromRef` lets Axum pull the auth engine out of our larger `AppState`.
impl axum::extract::FromRef<AppState> for SharedAuth<MemUserStore, MemSessionStore> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.auth)
    }
}

// ── Request / response shapes ─────────────────────────────────────────────────

/// Body for `POST /register`.
#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    /// `"realtor"`, `"lender"`, `"investor"`, or `"admin"`. Default: `"investor"`.
    #[serde(default)]
    role: Option<String>,
    /// Stored in the user's JSON `metadata` field for role-specific workflows.
    #[serde(default)]
    license_number: Option<String>,
}

/// Body for `POST /login`.
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

/// Response body for `POST /login` and `POST /refresh`.
#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: i64,
}

impl From<Session> for SessionResponse {
    fn from(s: Session) -> Self {
        Self { token: s.token, expires_at: s.expires_at }
    }
}

/// Public user representation — never leaks the password hash.
#[derive(Serialize)]
struct UserResponse {
    id: String,
    email: Option<String>,
    roles: Vec<String>,
    email_verified: bool,
    metadata: serde_json::Value,
}

impl From<AuthUser> for UserResponse {
    fn from(u: AuthUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            roles: u.roles.iter().map(|r| r.to_string()).collect(),
            email_verified: u.email_verified,
            metadata: u.metadata,
        }
    }
}

// ── Unified error type ────────────────────────────────────────────────────────

#[derive(Debug)]
enum AppError {
    Auth(AuthError),
    BadRequest(String),
}

impl From<AuthError> for AppError {
    fn from(e: AuthError) -> Self {
        AppError::Auth(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AppError::Auth(AuthError::UserNotFound) => {
                (StatusCode::NOT_FOUND, "user not found".to_string())
            }
            AppError::Auth(AuthError::InvalidCredentials) => {
                (StatusCode::UNAUTHORIZED, "invalid email or password".to_string())
            }
            AppError::Auth(AuthError::SessionInvalid) => {
                (StatusCode::UNAUTHORIZED, "session expired or not found".to_string())
            }
            AppError::Auth(AuthError::EmailNotVerified) => {
                (StatusCode::FORBIDDEN, "email address not verified".to_string())
            }
            AppError::Auth(AuthError::Forbidden(msg)) => (StatusCode::FORBIDDEN, msg),
            AppError::Auth(AuthError::PasswordPolicy(msg)) => (StatusCode::BAD_REQUEST, msg),
            AppError::Auth(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };
        (status, body).into_response()
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// `POST /register`
///
/// 1. Hash the password with Argon2id (`authsmith-password`).
/// 2. Call `auth.register()` which persists the user and fires the
///    `on_user_created` plugin hooks — the `EmailPlugin` sends a welcome email
///    and `WebhookPlugin` posts a `"user.created"` event automatically.
/// 3. Send a separate email-verification email directly (the token would
///    normally be generated and stored before building this URL).
async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    // Reject duplicate emails before touching the engine (avoids a 500 from
    // the provider error wrapping). A real DB adapter would use a UNIQUE index.
    if state.auth.find_user_by_email(&body.email).await?.is_some() {
        return Err(AppError::BadRequest("email already registered".into()));
    }

    // Hash with Argon2id (authsmith-password). Never pass a raw password to register().
    let hash = state
        .hasher
        .hash(&body.password)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let role = match body.role.as_deref() {
        Some("realtor") => Role::Realtor,
        Some("lender") => Role::Lender,
        Some("admin") => Role::Admin,
        _ => Role::Investor,
    };

    let mut metadata = serde_json::json!({});
    if let Some(lic) = &body.license_number {
        metadata["license_number"] = serde_json::json!(lic);
    }

    // register() persists the user and fires on_user_created on all plugins:
    //   • EmailPlugin  → sends welcome email via PrintEmailSender
    //   • WebhookPlugin → posts "user.created" event via PrintWebhookSender
    let user = state
        .auth
        .register(
            CreateUserInput::builder()
                .email(body.email)
                .password_hash(hash)
                .role(role)
                .metadata(metadata)
                .build(),
        )
        .await?;

    // Send a verification email directly (not via a plugin hook).
    // In production: generate a short-lived token, store it in the DB,
    // then embed it in the URL.
    let verify_url = format!(
        "http://localhost:3000/verify-email/{}?token=REPLACE_WITH_REAL_TOKEN",
        user.id
    );
    if let Some(msg) = state.email_templates.email_verification(&user, &verify_url) {
        // Fire-and-forget — don't fail registration if email delivery fails.
        let _ = state.email_sender.send(msg).await;
    }

    Ok((StatusCode::CREATED, Json(user.into())))
}

/// `POST /login`
///
/// 1. Look up the user by email.
/// 2. Verify the Argon2id hash in constant time.
/// 3. Create a session via `auth.login()`, which fires `on_login` hooks —
///    `WebhookPlugin` posts `"session.created"` automatically.
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    // Look up user — return the same error for missing user and wrong password
    // to prevent user-enumeration attacks.
    let user = state
        .auth
        .find_user_by_email(&body.email)
        .await?
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    // Retrieve the stored hash from the user provider (not exposed by AuthUser
    // to avoid accidental serialization). A real adapter would add a query method.
    let hash = state
        .auth
        .user_provider()
        .password_hash_for(&body.email)
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    // Constant-time Argon2 verification (authsmith-password).
    let valid = state
        .hasher
        .verify(&body.password, &hash)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    if !valid {
        return Err(AppError::Auth(AuthError::InvalidCredentials));
    }

    // Prefer X-Forwarded-For (set by reverse proxies like Nginx/Cloudflare).
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // login() = create_session() + fire on_login plugins.
    let (_, session) = state
        .auth
        .login(&user, SessionMeta { ip_address: ip, user_agent: ua })
        .await?;

    Ok(Json(session.into()))
}

/// `GET /me`
///
/// `AuthSession` is an Axum extractor from `authsmith-axum`.
/// It reads the `AuthUser` injected by `auth_middleware` and returns
/// `401 Unauthorized` automatically if no valid session is present.
async fn me(AuthSession(user): AuthSession) -> Json<UserResponse> {
    Json(user.into())
}

/// `GET /admin`
///
/// Protected by both `auth_middleware` (401 if no session) and
/// `require_role(Role::Admin)` (403 if wrong role) — both from `authsmith-axum`.
/// This handler only runs for authenticated admins.
async fn admin(AuthSession(user): AuthSession) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Welcome to the admin panel.",
        "admin_id": user.id,
        "roles": user.roles.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
    }))
}

/// `POST /refresh`
///
/// Rotates the session token — the old token is revoked immediately and a new
/// one is issued with a fresh TTL. Mitigates session fixation / replay attacks.
async fn refresh(
    State(state): State<AppState>,
    AuthSession(_user): AuthSession,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, AppError> {
    let token = extract_token(&headers).ok_or(AppError::Auth(AuthError::SessionInvalid))?;
    let new_session = state.auth.refresh_session(&token).await?;
    Ok(Json(new_session.into()))
}

/// `DELETE /logout`
///
/// Revokes the current session token. The `on_logout` hooks fire, including
/// `WebhookPlugin` posting `"session.revoked"`.
///
/// We re-extract the raw token from headers rather than storing it in
/// request extensions — the middleware only injects `AuthUser`.
async fn logout(
    State(state): State<AppState>,
    AuthSession(_user): AuthSession,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let token = extract_token(&headers).ok_or(AppError::Auth(AuthError::SessionInvalid))?;
    state.auth.logout(&token).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /users/:id/verify-email`
///
/// Admin-only: mark a user's email as verified.
/// Uses `auth.require_role()` for programmatic role enforcement — a complement
/// to the layer-based `require_role` middleware used on `/admin`.
async fn verify_email(
    State(state): State<AppState>,
    AuthSession(caller): AuthSession,
    Path(user_id): Path<String>,
) -> Result<Json<UserResponse>, AppError> {
    // Programmatic role check — returns 403 if caller is not Admin.
    state.auth.require_role(&caller, &Role::Admin)?;

    let user = state.auth.verify_email(&user_id).await?;
    Ok(Json(user.into()))
}

// ── Router ────────────────────────────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    // Public routes — no session required.
    let public = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    // Protected routes — auth_middleware injects AuthUser from a valid session.
    // Routes that return 401 when no session is present.
    let protected = Router::new()
        .route("/me", get(me))
        .route("/refresh", post(refresh))
        .route("/logout", delete(logout))
        .route("/users/{id}/verify-email", post(verify_email))
        // Role-gated: require_role(Role::Admin) returns 403 before the handler
        // runs if the authenticated user does not hold Role::Admin.
        .route(
            "/admin",
            get(admin).route_layer(middleware::from_fn(require_role(Role::Admin))),
        );

    Router::new()
        .merge(public)
        .merge(protected)
        // auth_middleware validates the session token (Cookie or Bearer) on
        // every request and injects AuthUser into request extensions.
        // Uses FromRef to extract SharedAuth<U, S> from AppState.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.auth),
            auth_middleware::<MemUserStore, MemSessionStore>,
        ))
        .with_state(state)
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .compact()
        .init();

    // ── Email plugin (authsmith-notify, smtp feature) ─────────────────────────
    //
    // PrintEmailSender prints emails to stdout. Swap for SmtpEmailSender in
    // production — the rest of the code is identical.
    let email_sender = Arc::new(PrintEmailSender);
    let email_templates = Arc::new(DefaultEmailTemplates {
        app_name: "DSCR Express".into(),
        base_url: "http://localhost:3000".into(),
    });

    let email_plugin = EmailPlugin::with_config(
        Arc::clone(&email_sender) as Arc<dyn EmailSender>,
        Arc::clone(&email_templates),
        EmailPluginConfig {
            send_welcome: true,      // fires on every register()
            send_login_alert: false, // set true in production
        },
    );

    // ── Webhook plugin (authsmith-notify, webhook feature) ────────────────────
    //
    // PrintWebhookSender logs events to stdout. Swap for AuthWebhookSender in
    // production — only the constructor changes.
    let webhook_plugin = WebhookPlugin::new(PrintWebhookSender);

    // ── AuthEngine ────────────────────────────────────────────────────────────
    //
    // Plugins are invoked in registration order on every auth lifecycle event.
    // In production, replace MemUserStore / MemSessionStore with:
    //   SqliteUserStore::new(pool.clone()) / SqliteSessionStore::new(pool)
    let auth = AuthEngine::builder()
        .user_provider(MemUserStore::default())
        .session_provider(MemSessionStore::default())
        .with_plugin(email_plugin)   // on_user_created → welcome email
                                     // on_login → login alert (if enabled)
        .with_plugin(webhook_plugin) // on_user_created → "user.created" POST
                                     // on_login        → "session.created" POST
                                     // on_logout       → "session.revoked" POST
        .config(AuthConfig {
            session_ttl_secs: 86_400,          // 24-hour sessions
            require_email_verification: false, // relax for this example
            password_min_length: 12,
            password_max_length: 128,
        })
        .build()?;

    let state = AppState {
        auth: Arc::new(auth),
        hasher: Arc::new(Argon2Hasher::default()),
        email_sender,
        email_templates,
    };

    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  AuthSmith basic-axum example  →  http://{addr}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  POST   /register                  create an account");
    println!("  POST   /login                     obtain a session token");
    println!("  GET    /me              🔒         current user profile");
    println!("  GET    /admin           🔒 Admin   admin-only panel");
    println!("  POST   /refresh         🔒         rotate session token");
    println!("  DELETE /logout          🔒         revoke session");
    println!("  POST   /users/:id/verify-email 🔒 Admin  mark email verified");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    axum::serve(listener, build_router(state)).await?;
    Ok(())
}
