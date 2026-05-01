//! # postgres-axum — Production AuthSmith Example
//!
//! A minimal but complete production-ready Axum server using:
//! - **Postgres** via `authsmith-db` (pg_setup — one-liner engine creation)
//! - **Argon2id** via `authsmith-password`
//! - **Auth middleware + extractors** via `authsmith-axum`
//! - **`AuthConfig::from_env()`** for zero-code configuration
//!
//! In a real project your `Cargo.toml` would be just:
//! ```toml
//! [dependencies]
//! authsmith = { version = "0.1", features = ["axum", "postgres", "password"] }
//! ```
//!
//! ## Setup
//!
//! ```sh
//! # Start Postgres (Docker)
//! docker run --rm -p 5432:5432 \
//!   -e POSTGRES_USER=auth -e POSTGRES_PASSWORD=auth -e POSTGRES_DB=authsmith \
//!   postgres:16-alpine
//!
//! # Configure (or put in .env)
//! export DATABASE_URL="postgresql://auth:auth@localhost/authsmith"
//! export AUTH_SESSION_TTL=86400
//! export AUTH_REQUIRE_EMAIL_VERIFICATION=false
//!
//! cargo run -p postgres-axum
//! ```
//!
//! ## Try the API
//!
//! ```sh
//! # Register
//! curl -s -X POST http://localhost:3000/register \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"alice@example.com","password":"correct-horse-battery","role":"admin"}' | jq
//!
//! # Login — capture token
//! TOKEN=$(curl -s -X POST http://localhost:3000/login \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"alice@example.com","password":"correct-horse-battery"}' | jq -r .token)
//!
//! # Authenticated profile
//! curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN" | jq
//!
//! # Admin panel (Alice is Admin so this works)
//! curl -s http://localhost:3000/admin -H "Authorization: Bearer $TOKEN" | jq
//!
//! # Rotate token
//! TOKEN=$(curl -s -X POST http://localhost:3000/refresh \
//!   -H "Authorization: Bearer $TOKEN" | jq -r .token)
//!
//! # Logout
//! curl -s -X DELETE http://localhost:3000/logout -H "Authorization: Bearer $TOKEN"
//! ```

use authsmith_axum::{auth_middleware, extract_token, require_role, AuthSession, SharedAuth};
use authsmith_core::{
    AuthConfig, AuthError, AuthProvider, AuthUser, CreateUserInput, PasswordHasher, Role,
    SessionMeta, SessionProvider,
};
use authsmith_db::{
    pg_setup,
    postgres::{PgSessionStore, PgUserStore},
};
use authsmith_password::Argon2Hasher;
use axum::{
    extract::{FromRef, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

// ── Application state ─────────────────────────────────────────────────────────

/// All shared application state. Kept in an `Arc` inside the Axum router.
///
/// Adding fields here (e.g. a Redis client, S3 config) is straightforward —
/// just implement `FromRef<AppState>` for each sub-state that a middleware
/// or extractor needs.
#[derive(Clone)]
struct AppState {
    /// The central auth engine wrapping PgUserStore + PgSessionStore.
    auth: SharedAuth<PgUserStore, PgSessionStore>,
    /// Argon2id hasher — a single instance is safe to share across threads.
    hasher: Arc<Argon2Hasher>,
}

/// Lets `auth_middleware` extract `SharedAuth` from `AppState` via Axum's
/// sub-state mechanism. Without this, every middleware layer would need the
/// full `AppState`.
impl FromRef<AppState> for SharedAuth<PgUserStore, PgSessionStore> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.auth)
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // 1. Connect to Postgres.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;

    // 2. Run migrations + wire user/session stores in one call.
    //    pg_setup() runs the bundled SQL migrations, then returns an
    //    AuthEngineBuilder pre-populated with PgUserStore + PgSessionStore.
    let auth = pg_setup(&pool)
        .await?
        // 3. Load config from env — AUTH_SESSION_TTL, AUTH_REQUIRE_EMAIL_VERIFICATION, etc.
        //    Falls back to safe defaults for any variable that is absent.
        .config(AuthConfig::from_env())
        .build()?;

    let state = AppState {
        auth: Arc::new(auth),
        hasher: Arc::new(Argon2Hasher::default()),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}

// ── Router ────────────────────────────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    // Public routes — no session required.
    let public = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    // Protected routes — `auth_middleware` must have run first.
    let protected = Router::new()
        .route("/me", get(me))
        .route("/refresh", post(refresh))
        .route("/logout", delete(logout))
        // Role gate: 403 before the handler runs if user is not Admin.
        .route(
            "/admin",
            get(admin_panel).route_layer(middleware::from_fn(require_role(Role::Admin))),
        );

    Router::new()
        .merge(public)
        .merge(protected)
        // auth_middleware validates the Bearer/Cookie token on every request
        // and injects `AuthUser` into request extensions for extractors.
        // FromRef pulls `SharedAuth` out of `AppState` automatically.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.auth),
            auth_middleware::<PgUserStore, PgSessionStore>,
        ))
        .with_state(state)
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterBody {
    email: String,
    password: String,
    /// One of: "admin", "realtor", "lender", "investor" (default).
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    expires_at: i64,
}

/// Public user shape — password hash is never included.
#[derive(Serialize)]
struct UserResponse {
    id: String,
    email: Option<String>,
    roles: Vec<String>,
    email_verified: bool,
}

impl From<AuthUser> for UserResponse {
    fn from(u: AuthUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            roles: u.roles.iter().map(|r| r.to_string()).collect(),
            email_verified: u.email_verified,
        }
    }
}

// ── Error handling ────────────────────────────────────────────────────────────

#[derive(Debug)]
enum AppError {
    Auth(AuthError),
    BadRequest(&'static str),
    Internal(anyhow::Error),
}

impl From<AuthError> for AppError {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg): (StatusCode, String) = match self {
            AppError::Auth(AuthError::UserNotFound) => {
                (StatusCode::NOT_FOUND, "user not found".into())
            }
            AppError::Auth(AuthError::InvalidCredentials) => {
                // Intentionally vague — prevents user enumeration.
                (StatusCode::UNAUTHORIZED, "invalid email or password".into())
            }
            AppError::Auth(AuthError::SessionInvalid) => {
                (StatusCode::UNAUTHORIZED, "session expired or invalid".into())
            }
            AppError::Auth(AuthError::EmailNotVerified) => {
                (StatusCode::FORBIDDEN, "email address not verified".into())
            }
            AppError::Auth(AuthError::Forbidden(m)) => (StatusCode::FORBIDDEN, m),
            AppError::Auth(AuthError::PasswordPolicy(m)) => (StatusCode::BAD_REQUEST, m),
            AppError::Auth(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.into()),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into())
            }
        };
        (status, msg).into_response()
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /register`
///
/// Hash the password → register → return the new user.
///
/// `pg_setup()` already set up the PgUserStore, so there is no boilerplate
/// here — just call `auth.register()` and it persists + fires plugins.
async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    // Hash with Argon2id before touching the engine.
    // The engine never handles raw passwords — hashing is always the caller's job.
    let hash = state
        .hasher
        .hash(&body.password)
        .map_err(|e| AppError::BadRequest(Box::leak(e.to_string().into_boxed_str())))?;

    let role = match body.role.as_deref() {
        Some("admin") => Role::Admin,
        Some("realtor") => Role::Realtor,
        Some("lender") => Role::Lender,
        _ => Role::Investor,
    };

    let user = state
        .auth
        .register(
            CreateUserInput::builder()
                .email(body.email)
                .password_hash(hash)
                .role(role)
                .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

/// `POST /login`
///
/// Look up → verify hash (constant-time) → create session → return token.
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Result<Json<TokenResponse>, AppError> {
    // Look up the user. Return the same error for "not found" and "wrong
    // password" to prevent user-enumeration timing attacks.
    let user = state
        .auth
        .find_user_by_email(&body.email)
        .await?
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    // Fetch the stored hash directly from the store (not on AuthUser — to
    // avoid accidental serialization of sensitive data).
    let hash = state
        .auth
        .user_provider()
        .find_password_hash_by_email(&body.email)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    // Argon2 constant-time verification (authsmith-password).
    let valid = state
        .hasher
        .verify(&body.password, &hash)
        .map_err(|_| AppError::Auth(AuthError::InvalidCredentials))?;

    if !valid {
        return Err(AppError::Auth(AuthError::InvalidCredentials));
    }

    // Capture IP + User-Agent for the session record.
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // create_session fires on_login plugin hooks.
    let session = state
        .auth
        .create_session(&user, SessionMeta { ip_address: ip, user_agent: ua, tenant_id: None })
        .await?;

    Ok(Json(TokenResponse { token: session.token, expires_at: session.expires_at }))
}

/// `GET /me`
///
/// `AuthSession` is injected by `auth_middleware`. If no valid session is
/// present the extractor returns 401 before this handler runs.
async fn me(AuthSession(user): AuthSession) -> Json<UserResponse> {
    Json(user.into())
}

/// `GET /admin`
///
/// Double-gated: `auth_middleware` (401) + `require_role(Role::Admin)` (403).
async fn admin_panel(AuthSession(user): AuthSession) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Welcome, admin.",
        "admin_id": user.id,
        "email": user.email,
    }))
}

/// `POST /refresh`
///
/// Rotates the session — old token revoked, fresh one issued with a new TTL.
/// Mitigates replay attacks from compromised tokens.
async fn refresh(
    State(state): State<AppState>,
    AuthSession(_): AuthSession,
    headers: HeaderMap,
) -> Result<Json<TokenResponse>, AppError> {
    let token = extract_token(&headers).ok_or(AppError::Auth(AuthError::SessionInvalid))?;
    let new_session = state.auth.refresh_session(&token).await?;
    Ok(Json(TokenResponse { token: new_session.token, expires_at: new_session.expires_at }))
}

/// `DELETE /logout`
async fn logout(
    State(state): State<AppState>,
    AuthSession(_): AuthSession,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let token = extract_token(&headers).ok_or(AppError::Auth(AuthError::SessionInvalid))?;
    state.auth.logout(&token).await?;
    Ok(StatusCode::NO_CONTENT)
}
