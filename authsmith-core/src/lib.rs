//! # AuthSmith Core
//!
//! Framework-agnostic, database-agnostic authentication primitives for Rust.
//! WASM-compatible — no heavy runtime dependencies.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! let auth = AuthEngine::builder()
//!     .user_provider(MyUserStore::new())
//!     .session_provider(MySessionStore::new())
//!     .config(AuthConfig { require_email_verification: true, ..Default::default() })
//!     .build()?;
//!
//! let user = auth.register(CreateUserInput {
//!     email: Some("alice@example.com".into()),
//!     ..Default::default()
//! }).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod engine;
pub use engine::{AuthEngine, AuthEngineBuilder};

// ── Core Types ────────────────────────────────────────────────────────────────

/// The central user identity — framework-agnostic and WASM-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    /// ULID-based unique identifier.
    pub id: String,
    pub email: Option<String>,
    /// libp2p PeerId as a string — enables decentralised identity.
    pub peer_id: Option<String>,
    pub roles: Vec<Role>,
    /// Arbitrary app-specific JSON (e.g. realtor licence #, NMLS number).
    pub metadata: serde_json::Value,
    pub email_verified: bool,
    /// Unix timestamp (seconds).
    pub created_at: i64,
    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

/// Built-in role variants; [`Role::Custom`] lets any app extend without forking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    Investor,
    Realtor,
    Lender,
    Admin,
    Custom(String),
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Investor => write!(f, "investor"),
            Role::Realtor => write!(f, "realtor"),
            Role::Lender => write!(f, "lender"),
            Role::Admin => write!(f, "admin"),
            Role::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// An active user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Cryptographically random token (32 bytes, base64url-encoded).
    pub token: String,
    pub user_id: String,
    /// Unix timestamp (seconds). Compare against current time to check validity.
    pub expires_at: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Unix timestamp (seconds).
    pub created_at: i64,
}

impl Session {
    /// Returns `true` if the session has not yet passed its expiry time.
    ///
    /// # Example
    /// ```
    /// use authsmith_core::Session;
    /// let session = Session {
    ///     token: "tok".into(), user_id: "usr".into(),
    ///     expires_at: 1_000, ip_address: None,
    ///     user_agent: None, created_at: 0,
    /// };
    /// assert!(session.is_valid(999));
    /// assert!(!session.is_valid(1_000));
    /// ```
    pub fn is_valid(&self, now_secs: i64) -> bool {
        self.expires_at > now_secs
    }
}

/// Metadata supplied at session-creation time (typically from the HTTP request).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMeta {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Input required to register a new user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserInput {
    pub email: Option<String>,
    /// A pre-hashed password — **never** pass a raw password to the provider.
    /// Use a [`PasswordHasher`] implementation before populating this field.
    pub password_hash: Option<String>,
    pub roles: Vec<Role>,
    /// Arbitrary app-specific JSON. Defaults to `null`.
    pub metadata: serde_json::Value,
    pub peer_id: Option<String>,
}

impl Default for CreateUserInput {
    fn default() -> Self {
        Self {
            email: None,
            password_hash: None,
            roles: Vec::new(),
            metadata: serde_json::Value::Null,
            peer_id: None,
        }
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Top-level configuration for an [`AuthEngine`] instance.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// How long (in seconds) a newly created session remains valid.
    /// Default: `86_400` (24 hours).
    pub session_ttl_secs: i64,
    /// When `true`, [`AuthEngine::create_session`] will reject users whose
    /// email address has not been verified. Default: `false`.
    pub require_email_verification: bool,
    /// Minimum accepted password length. Default: `8`.
    pub password_min_length: usize,
    /// Maximum accepted password length — guards against long-password DoS
    /// attacks (especially relevant for bcrypt). Default: `128`.
    pub password_max_length: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: 86_400,
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
        }
    }
}

// ── Error Types ───────────────────────────────────────────────────────────────

/// Errors returned by high-level [`AuthEngine`] operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("user not found")]
    UserNotFound,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("email address not verified")]
    EmailNotVerified,
    #[error("session expired or not found")]
    SessionInvalid,
    #[error("password policy violation: {0}")]
    PasswordPolicy(String),
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("provider error: {0}")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("plugin error: {0}")]
    Plugin(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur while constructing an [`AuthEngine`] via the builder.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("a user provider must be supplied before calling build()")]
    MissingUserProvider,
    #[error("a session provider must be supplied before calling build()")]
    MissingSessionProvider,
}

// ── Core Traits ───────────────────────────────────────────────────────────────

/// Implement this trait to connect any user-storage backend (SQLite, Postgres,
/// SurrealDB, in-memory, etc.).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error>;
    async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error>;
    async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error>;
    async fn delete_user(&self, id: &str) -> Result<(), Self::Error>;
}

/// Implement this trait to connect any session-storage backend.
/// Session storage is intentionally separate from user storage so each can be
/// scaled independently (e.g., Redis for sessions, Postgres for users).
#[async_trait]
pub trait SessionProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_session(
        &self,
        user_id: &str,
        expires_at: i64,
        meta: SessionMeta,
    ) -> Result<Session, Self::Error>;
    async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error>;
    async fn revoke_session(&self, token: &str) -> Result<(), Self::Error>;
    async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error>;
}

/// Lifecycle hooks — register multiple plugins on a single engine.
/// Plugins are invoked in registration order and any plugin error aborts the
/// operation, returning [`AuthError::Plugin`].
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// A stable, unique name for this plugin (used in logs and error messages).
    fn name(&self) -> &'static str;

    async fn on_user_created(
        &self,
        user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn on_login(
        &self,
        user: &AuthUser,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn on_logout(
        &self,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Abstraction over password hashing algorithms (Argon2, bcrypt, scrypt, …).
/// The `authsmith-password` crate provides an Argon2 implementation.
pub trait PasswordHasher: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Hash a raw password. Store the returned string; never store the raw value.
    fn hash(&self, password: &str) -> Result<String, Self::Error>;

    /// Verify a raw password against a stored hash.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, Self::Error>;
}

/// Pluggable secure token generation (used for session tokens, CSRF tokens, etc.).
pub trait TokenGenerator: Send + Sync {
    /// Produce a cryptographically secure random token string.
    fn generate(&self) -> String;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_is_valid_before_expiry() {
        let session = Session {
            token: "tok".into(),
            user_id: "usr".into(),
            expires_at: 1_000,
            ip_address: None,
            user_agent: None,
            created_at: 0,
        };
        assert!(session.is_valid(999));
        assert!(!session.is_valid(1_000)); // expired at boundary
        assert!(!session.is_valid(1_001));
    }

    #[test]
    fn role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Investor.to_string(), "investor");
        assert_eq!(Role::Realtor.to_string(), "realtor");
        assert_eq!(Role::Lender.to_string(), "lender");
        assert_eq!(Role::Custom("broker".into()).to_string(), "broker");
    }

    #[test]
    fn auth_config_defaults() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.session_ttl_secs, 86_400);
        assert_eq!(cfg.password_min_length, 8);
        assert_eq!(cfg.password_max_length, 128);
        assert!(!cfg.require_email_verification);
    }

    #[test]
    fn create_user_input_default_metadata_is_null() {
        let input = CreateUserInput::default();
        assert!(input.metadata.is_null());
        assert!(input.roles.is_empty());
    }
}
