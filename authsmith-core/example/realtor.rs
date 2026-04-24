
//! # Realtor Express — Realtor Registration Example
//!
//! Demonstrates the full `authsmith-core` API using in-memory providers.
//! In production, swap `MemoryUserStore` / `MemorySessionStore` for the
//! SQLite or Postgres adapters provided by `authsmith-db`.

use async_trait::async_trait;
use authsmith_core::{
    AuthConfig, AuthEngine, AuthError, AuthPlugin, AuthProvider, AuthUser,
    CreateUserInput, Role, Session, SessionMeta, SessionProvider,
};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn next_id(counter: &Mutex<u64>) -> String {
    // In production use the `ulid` crate.
    let mut c = counter.lock().unwrap();
    *c += 1;
    format!("usr_{c:06}")
}

fn generate_token(counter: &Mutex<u64>) -> String {
    // In production `authsmith-session` uses rand + base64url (32 bytes).
    let mut c = counter.lock().unwrap();
    *c += 1;
    let n: u64 = *c;
    format!("tok_{n:016x}")
}

// ── In-memory user store ──────────────────────────────────────────────────────

#[derive(Default)]
struct MemoryUserStore {
    users: Mutex<HashMap<String, AuthUser>>,
    counter: Mutex<u64>,
}

#[derive(Debug, thiserror::Error)]
enum UserStoreError {
    #[error("a user with that email already exists")]
    DuplicateEmail,
}

#[async_trait]
impl AuthProvider for MemoryUserStore {
    type Error = UserStoreError;

    async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error> {
        let mut users = self.users.lock().unwrap();

        if let Some(email) = &input.email {
            if users.values().any(|u| u.email.as_deref() == Some(email.as_str())) {
                return Err(UserStoreError::DuplicateEmail);
            }
        }

        let now = now_secs();
        let user = AuthUser {
            id: next_id(&self.counter),
            email: input.email,
            peer_id: input.peer_id,
            roles: input.roles,
            metadata: input.metadata,
            email_verified: false,
            created_at: now,
            updated_at: now,
        };
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self.users.lock().unwrap().get(id).cloned())
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error> {
        self.users.lock().unwrap().insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
        self.users.lock().unwrap().remove(id);
        Ok(())
    }
}

// ── In-memory session store ───────────────────────────────────────────────────

#[derive(Default)]
struct MemorySessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    counter: Mutex<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("session store error")]
struct SessionStoreError;

#[async_trait]
impl SessionProvider for MemorySessionStore {
    type Error = SessionStoreError;

    async fn create_session(
        &self,
        user_id: &str,
        expires_at: i64,
        meta: SessionMeta,
    ) -> Result<Session, Self::Error> {
        let session = Session {
            token: generate_token(&self.counter),
            user_id: user_id.to_string(),
            expires_at,
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            created_at: now_secs(),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.token.clone(), session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error> {
        Ok(self.sessions.lock().unwrap().get(token).cloned())
    }

    async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
        self.sessions.lock().unwrap().remove(token);
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, s| s.user_id != user_id);
        Ok(())
    }
}

// ── Audit-log plugin ──────────────────────────────────────────────────────────

struct AuditLogPlugin;

#[async_trait]
impl AuthPlugin for AuditLogPlugin {
    fn name(&self) -> &'static str {
        "audit-log"
    }

    async fn on_user_created(
        &self,
        user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("[audit] user_created  id={} email={:?}", user.id, user.email);
        Ok(())
    }

    async fn on_login(
        &self,
        user: &AuthUser,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!(
            "[audit] login         user_id={}  token={}…",
            user.id,
            &session.token[..12]
        );
        Ok(())
    }

    async fn on_logout(
        &self,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("[audit] logout        user_id={}", session.user_id);
        Ok(())
    }
}

// ── Role-guard plugin ─────────────────────────────────────────────────────────
// Example of a plugin that can reject a login based on business rules.

struct RequireRolePlugin {
    allowed: Vec<Role>,
}

#[async_trait]
impl AuthPlugin for RequireRolePlugin {
    fn name(&self) -> &'static str {
        "require-role"
    }

    async fn on_user_created(
        &self,
        _user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn on_login(
        &self,
        user: &AuthUser,
        _session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let permitted = user.roles.iter().any(|r| self.allowed.contains(r));
        if !permitted {
            return Err(format!(
                "user {} does not hold a required role for this application",
                user.id
            )
            .into());
        }
        Ok(())
    }

    async fn on_logout(
        &self,
        _session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Realtor Express — Realtor Auth Example ===\n");

    // Wire everything together.
    // Swap the in-memory providers for `authsmith-db` adapters in production.
    let auth = AuthEngine::builder()
        .user_provider(MemoryUserStore::default())
        .session_provider(MemorySessionStore::default())
        .with_plugin(AuditLogPlugin)
        .with_plugin(RequireRolePlugin {
            allowed: vec![Role::Realtor, Role::Lender, Role::Investor, Role::Admin],
        })
        .config(AuthConfig {
            session_ttl_secs: 86_400, // 24 hours
            require_email_verification: false, // relax for demo
            password_min_length: 10,
            ..Default::default()
        })
        .build()?;

    // ── 1. Register a realtor ─────────────────────────────────────────────────
    // The caller is responsible for hashing the password BEFORE this call.
    // Use `authsmith-password` (Argon2) — never pass a raw password here.
    println!("--- Register ---");
    let alice = auth
        .register(CreateUserInput {
            email: Some("alice@pacificcoastrealty.com".into()),
            password_hash: Some("$argon2id$v=19$…placeholder".into()),
            roles: vec![Role::Realtor],
            metadata: serde_json::json!({
                "license_number": "CA-DRE-01234567",
                "brokerage":       "Pacific Coast Realty",
                "years_active":    7
            }),
            ..Default::default()
        })
        .await?;

    println!(
        "Registered: id={} email={:?} roles={:?}\n",
        alice.id, alice.email, alice.roles
    );

    // ── 2. Create a session (simulates successful credential verification) ────
    // In a real Axum handler the IP comes from `ConnectInfo<SocketAddr>` and
    // the user-agent from the `User-Agent` request header — never hardcoded.
    // We read from env vars here so the example stays runnable anywhere.
    println!("--- Login ---");
    let client_ip = std::env::var("CLIENT_IP").ok(); // e.g. export CLIENT_IP=1.2.3.4
    let client_ua = std::env::var("CLIENT_UA")
        .ok()
        .or_else(|| Some("Realtor Express/1.0 (example)".into()));

    let session = auth
        .create_session(
            &alice,
            SessionMeta {
                ip_address: client_ip,
                user_agent: client_ua,
            },
        )
        .await?;

    println!("Session token : {}…", &session.token[..16]);
    println!("Expires at    : {} (unix secs)\n", session.expires_at);

    // ── 3. Validate a token — what an Axum extractor or middleware does ───────
    println!("--- Validate token ---");
    let validated = auth.validate_session(&session.token).await?;
    println!("Token valid   : user_id={}\n", validated.user_id);

    // ── 4. Resolve token → full user ─────────────────────────────────────────
    println!("--- Resolve current user ---");
    let current = auth.get_current_user(&session.token).await?;
    println!(
        "Current user  : email={}",
        current.email.as_deref().unwrap_or("-")
    );
    println!(
        "Is Realtor?   : {}",
        AuthEngine::<MemoryUserStore, MemorySessionStore>::has_role(&current, &Role::Realtor)
    );
    let license = current.metadata["license_number"]
        .as_str()
        .unwrap_or("unknown");
    println!("License #     : {license}");
    println!(
        "Brokerage     : {}\n",
        current.metadata["brokerage"].as_str().unwrap_or("-")
    );

    // ── 5. Role gate ──────────────────────────────────────────────────────────
    println!("--- Role gate ---");
    if !AuthEngine::<MemoryUserStore, MemorySessionStore>::has_role(&current, &Role::Admin) {
        println!("Admin panel   : access denied (Alice is Realtor, not Admin)\n");
    }

    // ── 6. Logout ─────────────────────────────────────────────────────────────
    println!("--- Logout ---");
    auth.logout(&session.token).await?;

    // ── 7. Confirm the session is gone ────────────────────────────────────────
    println!("--- Confirm invalidation ---");
    match auth.validate_session(&session.token).await {
        Err(AuthError::SessionInvalid) => println!("Session correctly invalidated ✓"),
        Ok(_) => println!("BUG: session still valid after logout"),
        Err(e) => println!("Unexpected error: {e}"),
    }

    Ok(())
}
