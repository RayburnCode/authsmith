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
//!     .config(
//!         AuthConfig::builder()
//!             .require_email_verification(true)
//!             .session_ttl_secs(86_400)
//!             .build()
//!     )
//!     .build()?;
//!
//! // One-shot registration via the fluent builder:
//! let user = auth.register(
//!     CreateUserInput::builder()
//!         .email("alice@example.com")
//!         .role(Role::Realtor)
//!         .metadata_field("license", "CA-12345")
//!         .build()
//! ).await?;
//!
//! // One-shot login (authenticate + create session):
//! let (user, session) = auth.login(&user, SessionMeta::default()).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod engine;
pub use engine::{AuthEngine, AuthEngineBuilder};

#[cfg(feature = "session")]
pub mod session;

// ── Core Types ────────────────────────────────────────────────────────────────

/// The central user identity — framework-agnostic and WASM-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    /// ULID-based unique identifier.
    pub id: String,
    pub email: Option<String>,
    /// libp2p PeerId as a string — enables decentralised identity.
    pub peer_id: Option<String>,
    /// Optional tenant scope — set when this user belongs to a specific tenant.
    /// `None` means single-tenant (the default). Use this to scope queries in
    /// multi-tenant deployments without forking the provider.
    pub tenant_id: Option<String>,
    pub roles: Vec<Role>,
    /// Arbitrary app-specific JSON (e.g. realtor licence #, NMLS number).
    pub metadata: serde_json::Value,
    pub email_verified: bool,
    /// Unix timestamp (seconds).
    pub created_at: i64,
    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

impl AuthUser {
    /// Returns `true` if this user holds the given role.
    ///
    /// Prefer this over manual `user.roles.contains(role)` for readability.
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }

    /// Shorthand for `has_role(&Role::Admin)`.
    pub fn is_admin(&self) -> bool {
        self.has_role(&Role::Admin)
    }

    /// Add a role if not already present. No-op when the user already holds it.
    pub fn add_role(&mut self, role: Role) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    /// Remove all occurrences of `role` from this user's role list.
    pub fn remove_role(&mut self, role: &Role) {
        self.roles.retain(|r| r != role);
    }

    /// Read a typed value from the user's JSON `metadata` map.
    ///
    /// Returns `None` if the key is absent or deserialisation fails.
    ///
    /// # Example
    /// ```rust,ignore
    /// let license: Option<String> = user.metadata_get("license");
    /// ```
    pub fn metadata_get<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.metadata
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Insert or overwrite a key in the user's JSON `metadata` map.
    ///
    /// If `metadata` is not already an object, it is replaced with one.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if `value` cannot be serialised.
    ///
    /// # Example
    /// ```rust,ignore
    /// user.metadata_set("license", "CA-12345")?;
    /// user.metadata_set("nmls", 1234567_u32)?;
    /// ```
    pub fn metadata_set<T>(&mut self, key: &str, value: T) -> Result<(), serde_json::Error>
    where
        T: serde::Serialize,
    {
        let v = serde_json::to_value(value)?;
        match &mut self.metadata {
            serde_json::Value::Object(map) => {
                map.insert(key.to_string(), v);
            }
            other => {
                *other = serde_json::json!({ key: v });
            }
        }
        Ok(())
    }
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

impl std::str::FromStr for Role {
    /// Any non-empty string is accepted — unknown roles map to [`Role::Custom`].
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "investor" => Role::Investor,
            "realtor" => Role::Realtor,
            "lender" => Role::Lender,
            "admin" => Role::Admin,
            other => Role::Custom(other.to_string()),
        })
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
    /// Optional tenant scope — mirrors [`AuthUser::tenant_id`].
    /// Used by session providers to filter sessions by tenant.
    pub tenant_id: Option<String>,
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
    ///     tenant_id: None,
    /// };
    /// assert!(session.is_valid(999));
    /// assert!(!session.is_valid(1_000));
    /// ```
    pub fn is_valid(&self, now_secs: i64) -> bool {
        self.expires_at > now_secs
    }

    /// Returns `true` if this session belongs to the given tenant.
    ///
    /// A session with `tenant_id = None` is considered to match any tenant
    /// scope — useful for single-tenant deployments.
    pub fn belongs_to_tenant(&self, tenant_id: &str) -> bool {
        self.tenant_id.as_deref().map_or(true, |t| t == tenant_id)
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
    /// Optional tenant scope — forward this from the registration context so
    /// the provider can store and index the user under the correct tenant.
    pub tenant_id: Option<String>,
}

impl Default for CreateUserInput {
    fn default() -> Self {
        Self {
            email: None,
            password_hash: None,
            roles: Vec::new(),
            metadata: serde_json::Value::Null,
            peer_id: None,
            tenant_id: None,
        }
    }
}

impl CreateUserInput {
    /// Start building a [`CreateUserInput`] with a fluent API.
    ///
    /// # Example
    /// ```rust,ignore
    /// let input = CreateUserInput::builder()
    ///     .email("alice@example.com")
    ///     .role(Role::Realtor)
    ///     .metadata_field("license", "CA-98765")
    ///     .build();
    /// ```
    pub fn builder() -> CreateUserInputBuilder {
        CreateUserInputBuilder::default()
    }
}

/// Fluent builder for [`CreateUserInput`].
///
/// Obtained via [`CreateUserInput::builder()`].
#[derive(Debug, Default)]
pub struct CreateUserInputBuilder {
    email: Option<String>,
    password_hash: Option<String>,
    roles: Vec<Role>,
    metadata: serde_json::Value,
    peer_id: Option<String>,
    tenant_id: Option<String>,
}

impl CreateUserInputBuilder {
    /// Set the user's email address.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set a pre-hashed password. **Never pass a raw password here.**
    pub fn password_hash(mut self, hash: impl Into<String>) -> Self {
        self.password_hash = Some(hash.into());
        self
    }

    /// Add a single role.
    pub fn role(mut self, role: Role) -> Self {
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
        self
    }

    /// Replace the entire role list.
    pub fn roles(mut self, roles: Vec<Role>) -> Self {
        self.roles = roles;
        self
    }

    /// Set the entire metadata blob as a raw [`serde_json::Value`].
    pub fn metadata(mut self, value: serde_json::Value) -> Self {
        self.metadata = value;
        self
    }

    /// Insert a single key/value pair into the metadata object.
    ///
    /// If metadata is not yet an object, it is initialised as one.
    /// Silently drops the field if `value` cannot be serialised.
    pub fn metadata_field<T: serde::Serialize>(mut self, key: &str, value: T) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            match &mut self.metadata {
                serde_json::Value::Object(map) => {
                    map.insert(key.to_string(), v);
                }
                other => {
                    *other = serde_json::json!({ key: v });
                }
            }
        }
        self
    }

    /// Set a libp2p PeerId string for decentralised identity.
    pub fn peer_id(mut self, peer_id: impl Into<String>) -> Self {
        self.peer_id = Some(peer_id.into());
        self
    }

    /// Scope this user to a tenant.
    ///
    /// Pass the tenant identifier used by your provider (e.g. an organisation
    /// slug or ULID). Omit for single-tenant deployments.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Consume the builder and produce a [`CreateUserInput`].
    pub fn build(self) -> CreateUserInput {
        CreateUserInput {
            email: self.email,
            password_hash: self.password_hash,
            roles: self.roles,
            metadata: self.metadata,
            peer_id: self.peer_id,
            tenant_id: self.tenant_id,
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

impl AuthConfig {
    /// Start building an [`AuthConfig`] with a fluent API.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = AuthConfig::builder()
    ///     .session_ttl_secs(3_600)
    ///     .require_email_verification(true)
    ///     .password_min_length(10)
    ///     .build();
    /// ```
    pub fn builder() -> AuthConfigBuilder {
        AuthConfigBuilder::default()
    }
}

/// Fluent builder for [`AuthConfig`].
///
/// Obtained via [`AuthConfig::builder()`]. Starts from [`AuthConfig::default()`].
#[derive(Debug)]
pub struct AuthConfigBuilder {
    inner: AuthConfig,
}

impl Default for AuthConfigBuilder {
    fn default() -> Self {
        Self {
            inner: AuthConfig::default(),
        }
    }
}

impl AuthConfigBuilder {
    /// Session time-to-live in seconds. Default: `86_400` (24 h).
    pub fn session_ttl_secs(mut self, secs: i64) -> Self {
        self.inner.session_ttl_secs = secs;
        self
    }

    /// Reject logins from users whose email is not yet verified. Default: `false`.
    pub fn require_email_verification(mut self, required: bool) -> Self {
        self.inner.require_email_verification = required;
        self
    }

    /// Minimum password length enforced by [`PasswordPolicy`]. Default: `8`.
    pub fn password_min_length(mut self, len: usize) -> Self {
        self.inner.password_min_length = len;
        self
    }

    /// Maximum password length enforced by [`PasswordPolicy`]. Default: `128`.
    pub fn password_max_length(mut self, len: usize) -> Self {
        self.inner.password_max_length = len;
        self
    }

    /// Consume the builder and return the final [`AuthConfig`].
    pub fn build(self) -> AuthConfig {
        self.inner
    }
}

// ── Password Policy ───────────────────────────────────────────────────────────

/// Stateless password policy rules, evaluated against plaintext passwords
/// **before** they are hashed.
///
/// Embed this in your [`AuthConfig`] or use it standalone:
///
/// ```rust
/// use authsmith_core::PasswordPolicy;
/// let policy = PasswordPolicy::default();
/// assert!(policy.validate("Correct-Horse-Battery9").is_ok());
/// assert!(policy.validate("short").is_err());
/// ```
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum number of characters. Default: `8`.
    pub min_length: usize,
    /// Maximum number of characters — guards against bcrypt DoS. Default: `128`.
    pub max_length: usize,
    /// At least one ASCII uppercase letter required. Default: `false`.
    pub require_uppercase: bool,
    /// At least one ASCII lowercase letter required. Default: `false`.
    pub require_lowercase: bool,
    /// At least one ASCII digit required. Default: `false`.
    pub require_digit: bool,
    /// At least one special character (`!@#$%^&*…`) required. Default: `false`.
    pub require_special: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
        }
    }
}

impl PasswordPolicy {
    /// Validate `password` against all active rules.
    ///
    /// # Errors
    /// Returns [`AuthError::PasswordPolicy`] with a human-readable message
    /// describing the **first** violated rule.
    pub fn validate(&self, password: &str) -> Result<(), AuthError> {
        let len = password.chars().count();
        if len < self.min_length {
            return Err(AuthError::PasswordPolicy(format!(
                "password must be at least {} characters",
                self.min_length
            )));
        }
        if len > self.max_length {
            return Err(AuthError::PasswordPolicy(format!(
                "password must be at most {} characters",
                self.max_length
            )));
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(AuthError::PasswordPolicy(
                "password must contain at least one uppercase letter".into(),
            ));
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(AuthError::PasswordPolicy(
                "password must contain at least one lowercase letter".into(),
            ));
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::PasswordPolicy(
                "password must contain at least one digit".into(),
            ));
        }
        if self.require_special
            && !password
                .chars()
                .any(|c| "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\\\"".contains(c))
        {
            return Err(AuthError::PasswordPolicy(
                "password must contain at least one special character".into(),
            ));
        }
        Ok(())
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
    /// The caller is not authenticated (no valid session).
    #[error("not authenticated")]
    Unauthorized,
    /// The caller is authenticated but lacks the required role/permission.
    #[error("forbidden: {0}")]
    Forbidden(String),
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
    /// Return all sessions currently held by `user_id`.
    ///
    /// Used for multi-session management ("sign out everywhere" UIs, admin
    /// dashboards, and audit views). Implementations should return both active
    /// and expired sessions or only unexpired ones — document which.
    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<Session>, Self::Error>;
}

/// Lifecycle hooks — register multiple plugins on a single engine.
/// Plugins are invoked in registration order and any plugin error aborts the
/// operation, returning [`AuthError::Plugin`].
///
/// All hook methods have default no-op implementations so you only need to
/// override the ones you care about. Only [`AuthPlugin::name`] is required.
///
/// # Example
/// ```rust,ignore
/// struct AuditLog;
///
/// #[async_trait]
/// impl AuthPlugin for AuditLog {
///     fn name(&self) -> &'static str { "audit-log" }
///
///     async fn on_login(&self, user: &AuthUser, session: &Session)
///         -> Result<(), Box<dyn std::error::Error + Send + Sync>>
///     {
///         println!("[audit] {} logged in (session {})", user.id, session.token);
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// A stable, unique name for this plugin (used in logs and error messages).
    fn name(&self) -> &'static str;

    /// Called after a new user is persisted. No-op by default.
    async fn on_user_created(
        &self,
        _user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Called after a session is created for an authenticated user. No-op by default.
    async fn on_login(
        &self,
        _user: &AuthUser,
        _session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Called after a session is revoked. No-op by default.
    async fn on_logout(
        &self,
        _session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Called when a login attempt fails (bad password, unknown email, etc.).
    ///
    /// `email` is the address that was attempted (may be `None` for peer-based
    /// login). `reason` is a short human-readable description of the failure.
    /// Use this to drive audit logs, rate-limiting counters, and alerting.
    async fn on_login_failed(
        &self,
        _email: Option<&str>,
        _reason: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    /// Called when a user account is banned.
    ///
    /// Use this to revoke active sessions, send notifications, and write audit
    /// events. Fired by [`AuthEngine::ban_user`] (v0.8).
    async fn on_user_banned(
        &self,
        _user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
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

// ── Framework-agnostic HTTP token extraction ──────────────────────────────────

/// Utilities for extracting auth tokens from raw HTTP header strings.
///
/// These functions are framework-agnostic and WASM-safe — they operate on
/// plain string slices so any HTTP framework adapter can delegate to them
/// instead of duplicating the parsing logic.
///
/// # Example
/// ```
/// use authsmith_core::http::{extract_bearer_token, extract_cookie};
///
/// let token = extract_bearer_token("Bearer my-session-tok");
/// assert_eq!(token, Some("my-session-tok"));
///
/// let cookie = extract_cookie("other=x; authsmith_session=abc123; foo=bar", "authsmith_session");
/// assert_eq!(cookie.as_deref(), Some("abc123"));
/// ```
pub mod http {
    /// Extract a bearer token from a raw `Authorization` header value.
    ///
    /// Returns the token slice (trimmed) when the value starts with `"Bearer "`;
    /// returns `None` otherwise.
    pub fn extract_bearer_token(authorization: &str) -> Option<&str> {
        authorization.strip_prefix("Bearer ").map(str::trim)
    }

    /// Extract a named cookie value from a raw `Cookie` header value.
    ///
    /// Handles multiple cookies separated by `";"`. Returns `None` if the
    /// cookie name is absent.
    pub fn extract_cookie(cookie_header: &str, name: &str) -> Option<String> {
        for pair in cookie_header.split(';') {
            let mut kv = pair.trim().splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                if k.trim() == name {
                    return Some(v.trim().to_owned());
                }
            }
        }
        None
    }
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
            tenant_id: None,
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
    fn role_from_str_roundtrips() {
        use std::str::FromStr;
        assert_eq!(Role::from_str("admin").unwrap(), Role::Admin);
        assert_eq!(Role::from_str("investor").unwrap(), Role::Investor);
        assert_eq!(Role::from_str("realtor").unwrap(), Role::Realtor);
        assert_eq!(Role::from_str("lender").unwrap(), Role::Lender);
        assert_eq!(
            Role::from_str("broker").unwrap(),
            Role::Custom("broker".into())
        );
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
    fn auth_config_builder() {
        let cfg = AuthConfig::builder()
            .session_ttl_secs(3_600)
            .require_email_verification(true)
            .password_min_length(12)
            .build();
        assert_eq!(cfg.session_ttl_secs, 3_600);
        assert!(cfg.require_email_verification);
        assert_eq!(cfg.password_min_length, 12);
        assert_eq!(cfg.password_max_length, 128); // unchanged default
    }

    #[test]
    fn create_user_input_default_metadata_is_null() {
        let input = CreateUserInput::default();
        assert!(input.metadata.is_null());
        assert!(input.roles.is_empty());
    }

    #[test]
    fn create_user_input_builder() {
        let input = CreateUserInput::builder()
            .email("alice@example.com")
            .role(Role::Realtor)
            .role(Role::Realtor) // deduped
            .metadata_field("license", "CA-12345")
            .build();
        assert_eq!(input.email.as_deref(), Some("alice@example.com"));
        assert_eq!(input.roles, vec![Role::Realtor]);
        assert_eq!(input.metadata["license"], "CA-12345");
    }

    #[test]
    fn auth_user_role_helpers() {
        let mut user = AuthUser {
            id: "u1".into(),
            email: None,
            peer_id: None,
            tenant_id: None,
            roles: vec![Role::Realtor],
            metadata: serde_json::Value::Null,
            email_verified: false,
            created_at: 0,
            updated_at: 0,
        };
        assert!(user.has_role(&Role::Realtor));
        assert!(!user.is_admin());

        user.add_role(Role::Admin);
        assert!(user.is_admin());

        user.add_role(Role::Admin); // no-op
        assert_eq!(user.roles.len(), 2);

        user.remove_role(&Role::Admin);
        assert!(!user.is_admin());
        assert_eq!(user.roles.len(), 1);
    }

    #[test]
    fn auth_user_metadata_helpers() {
        let mut user = AuthUser {
            id: "u1".into(),
            email: None,
            peer_id: None,
            tenant_id: None,
            roles: vec![],
            metadata: serde_json::Value::Null,
            email_verified: false,
            created_at: 0,
            updated_at: 0,
        };

        user.metadata_set("license", "CA-98765").unwrap();
        assert_eq!(
            user.metadata_get::<String>("license").as_deref(),
            Some("CA-98765")
        );

        user.metadata_set("nmls", 1_234_567_u32).unwrap();
        assert_eq!(user.metadata_get::<u32>("nmls"), Some(1_234_567));
        assert_eq!(user.metadata_get::<String>("missing"), None);
    }

    #[test]
    fn password_policy_validates_length() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("correct").is_err()); // 7 chars
        assert!(policy.validate("correct!").is_ok()); // 8 chars
        assert!(policy.validate(&"x".repeat(128)).is_ok());
        assert!(policy.validate(&"x".repeat(129)).is_err());
    }

    #[test]
    fn password_policy_character_rules() {
        let policy = PasswordPolicy {
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            ..Default::default()
        };
        assert!(policy.validate("alllowercase").is_err()); // no upper or digit
        assert!(policy.validate("Uppercase1!").is_ok());
        assert!(policy.validate("NoSpecial1A").is_err());
    }

    #[test]
    fn http_extract_bearer_token() {
        assert_eq!(
            crate::http::extract_bearer_token("Bearer tok123"),
            Some("tok123")
        );
        assert_eq!(
            crate::http::extract_bearer_token("Basic dXNlcjpwYXNz"),
            None
        );
        assert_eq!(crate::http::extract_bearer_token(""), None);
    }

    #[test]
    fn http_extract_cookie() {
        let header = "session=x; authsmith_session=abc123; foo=bar";
        assert_eq!(
            crate::http::extract_cookie(header, "authsmith_session").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            crate::http::extract_cookie(header, "missing").as_deref(),
            None
        );
    }

    #[test]
    fn session_belongs_to_tenant() {
        let mut session = Session {
            token: "tok".into(),
            user_id: "usr".into(),
            expires_at: 9_999_999_999,
            ip_address: None,
            user_agent: None,
            created_at: 0,
            tenant_id: Some("acme".into()),
        };
        assert!(session.belongs_to_tenant("acme"));
        assert!(!session.belongs_to_tenant("other"));
        // None tenant_id matches any scope (single-tenant default)
        session.tenant_id = None;
        assert!(session.belongs_to_tenant("anything"));
    }
}
