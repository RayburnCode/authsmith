//! `AuthEngine` — the central orchestrator for all auth operations.
//!
//! Build one via [`AuthEngine::builder()`] and keep it behind an `Arc` in
//! shared application state (e.g. an Axum router extension).

use std::sync::Arc;

use crate::{
    AuthConfig, AuthError, AuthPlugin, AuthProvider, AuthUser, ConfigError, CreateUserInput,
    Role, Session, SessionMeta, SessionProvider,
};

// ── Engine ────────────────────────────────────────────────────────────────────

/// Central orchestrator — generic over user and session backends.
///
/// Construct via [`AuthEngine::builder()`].
pub struct AuthEngine<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    pub(crate) user_provider: Arc<U>,
    pub(crate) session_provider: Arc<S>,
    pub(crate) plugins: Vec<Box<dyn AuthPlugin>>,
    pub(crate) config: AuthConfig,
}

impl<U, S> AuthEngine<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    /// Start building an [`AuthEngine`].
    pub fn builder() -> AuthEngineBuilder<U, S> {
        AuthEngineBuilder::default()
    }

    // ── High-level operations ─────────────────────────────────────────────────

    /// Register a new user account and fire `on_user_created` on all plugins.
    ///
    /// The caller must supply a **pre-hashed** password via
    /// [`CreateUserInput::password_hash`]. Use a [`crate::PasswordHasher`]
    /// implementation (e.g. from `authsmith-password`) before calling this.
    ///
    /// # Errors
    /// Returns [`AuthError::Provider`] if the backing store fails, or
    /// [`AuthError::Plugin`] if any plugin hook fails.
    pub async fn register(&self, input: CreateUserInput) -> Result<AuthUser, AuthError> {
        let user = self
            .user_provider
            .create_user(input)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?;

        for plugin in &self.plugins {
            plugin
                .on_user_created(&user)
                .await
                .map_err(AuthError::Plugin)?;
        }

        Ok(user)
    }

    /// Create a new session for an already-authenticated user and fire
    /// `on_login` on all plugins.
    ///
    /// # Errors
    /// Returns [`AuthError::EmailNotVerified`] if `require_email_verification`
    /// is set and the user's email is unverified.
    /// Returns [`AuthError::Forbidden`] if the user account is banned.
    pub async fn create_session(
        &self,
        user: &AuthUser,
        meta: SessionMeta,
    ) -> Result<Session, AuthError> {
        if user.banned {
            return Err(AuthError::Forbidden("account is banned".to_owned()));
        }
        if self.config.require_email_verification && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        let expires_at = now_secs() + self.config.session_ttl_secs;

        // Inherit the user's tenant scope when the caller didn't specify one.
        let meta = SessionMeta {
            tenant_id: meta.tenant_id.or_else(|| user.tenant_id.clone()),
            ..meta
        };

        let session = self
            .session_provider
            .create_session(&user.id, expires_at, meta)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?;

        for plugin in &self.plugins {
            plugin
                .on_login(user, &session)
                .await
                .map_err(AuthError::Plugin)?;
        }

        Ok(session)
    }

    /// Validate an incoming session token.
    ///
    /// # Errors
    /// Returns [`AuthError::SessionInvalid`] if the token is unknown or expired.
    pub async fn validate_session(&self, token: &str) -> Result<Session, AuthError> {
        let session = self
            .session_provider
            .get_session(token)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::SessionInvalid)?;

        if !session.is_valid(now_secs()) {
            return Err(AuthError::SessionInvalid);
        }

        Ok(session)
    }

    /// Resolve a session token to the owning [`AuthUser`].
    ///
    /// Validates the session then fetches the user — convenient for middleware.
    pub async fn get_current_user(&self, token: &str) -> Result<AuthUser, AuthError> {
        let session = self.validate_session(token).await?;

        self.user_provider
            .find_user_by_id(&session.user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::UserNotFound)
    }

    /// Revoke a single session token and fire `on_logout` on all plugins.
    pub async fn logout(&self, token: &str) -> Result<(), AuthError> {
        let session = self
            .session_provider
            .get_session(token)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::SessionInvalid)?;

        self.session_provider
            .revoke_session(token)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?;

        for plugin in &self.plugins {
            plugin
                .on_logout(&session)
                .await
                .map_err(AuthError::Plugin)?;
        }

        Ok(())
    }

    /// Revoke every active session for a user — "sign out everywhere".
    pub async fn logout_all(&self, user_id: &str) -> Result<(), AuthError> {
        self.session_provider
            .revoke_all_sessions(user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// List all sessions for a user — powers multi-session management UIs.
    ///
    /// Returns every session the provider has on record for `user_id`. Whether
    /// expired sessions are included depends on the provider implementation —
    /// see its documentation. Active sessions can be filtered with
    /// [`Session::is_valid`].
    ///
    /// # Example
    /// ```rust,ignore
    /// let sessions = auth.list_sessions(&user.id).await?;
    /// let active: Vec<_> = sessions.iter().filter(|s| s.is_valid(now_secs())).collect();
    /// ```
    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<Session>, AuthError> {
        self.session_provider
            .list_sessions_for_user(user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// List all active sessions across every user — admin dashboard only.
    pub async fn list_all_sessions(&self) -> Result<Vec<Session>, AuthError> {
        self.session_provider
            .list_all_sessions()
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// List every user in the system — admin dashboard only.
    pub async fn list_all_users(&self) -> Result<Vec<AuthUser>, AuthError> {
        self.user_provider
            .list_users()
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// Ban a user: set their `banned` flag and fire `on_user_banned` on all plugins.
    ///
    /// Banned users are rejected by [`AuthEngine::create_session`] so they
    /// cannot obtain new sessions. Existing sessions remain valid until they
    /// expire or are individually revoked.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if no user with `user_id` exists.
    pub async fn ban_user(&self, user_id: &str) -> Result<AuthUser, AuthError> {
        let mut user = self
            .user_provider
            .find_user_by_id(user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::UserNotFound)?;

        user.banned = true;

        let user = self
            .user_provider
            .update_user(user)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?;

        for plugin in &self.plugins {
            plugin
                .on_user_banned(&user)
                .await
                .map_err(AuthError::Plugin)?;
        }

        Ok(user)
    }

    // ── Convenience operations ────────────────────────────────────────────────

    /// One-shot login: create a session for an already-authenticated user and
    /// fire `on_login` on all plugins.
    ///
    /// This combines [`create_session`](Self::create_session) with the email
    /// verification guard and plugin hooks into a single ergonomic call.
    ///
    /// # Example
    /// ```rust,ignore
    /// let user = auth.find_user_by_email("alice@example.com").await?.unwrap();
    /// // caller must verify password via PasswordHasher before this point
    /// let (user, session) = auth.login(&user, SessionMeta::default()).await?;
    /// ```
    pub async fn login(
        &self,
        user: &AuthUser,
        meta: SessionMeta,
    ) -> Result<(AuthUser, Session), AuthError> {
        let session = self.create_session(user, meta).await?;
        Ok((user.clone(), session))
    }

    /// Look up a user by email address.
    ///
    /// Returns `Ok(None)` when no user with that email exists.
    pub async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.user_provider
            .find_user_by_email(email)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// Mark a user's email address as verified and persist the change.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if no user with `user_id` exists.
    pub async fn verify_email(&self, user_id: &str) -> Result<AuthUser, AuthError> {
        let mut user = self
            .user_provider
            .find_user_by_id(user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::UserNotFound)?;

        user.email_verified = true;

        self.user_provider
            .update_user(user)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// Replace a user's role list and persist the change.
    ///
    /// Overwrites the existing roles entirely — combine with
    /// [`AuthUser::add_role`] / [`AuthUser::remove_role`] if you need
    /// incremental mutations.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if no user with `user_id` exists.
    pub async fn set_user_roles(
        &self,
        user_id: &str,
        roles: Vec<Role>,
    ) -> Result<AuthUser, AuthError> {
        let mut user = self
            .user_provider
            .find_user_by_id(user_id)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?
            .ok_or(AuthError::UserNotFound)?;

        user.roles = roles;

        self.user_provider
            .update_user(user)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// Rotate a session: revoke the current token and issue a fresh one with
    /// the same metadata and a new TTL window.
    ///
    /// This implements token rotation — the old token becomes invalid
    /// immediately, mitigating replay attacks. Suitable for "remember me"
    /// refresh flows.
    ///
    /// # Errors
    /// Returns [`AuthError::SessionInvalid`] if the token is unknown or expired.
    pub async fn refresh_session(&self, token: &str) -> Result<Session, AuthError> {
        let old = self.validate_session(token).await?;

        // Revoke the old token first (token rotation).
        self.session_provider
            .revoke_session(token)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))?;

        let meta = SessionMeta {
            ip_address: old.ip_address.clone(),
            user_agent: old.user_agent.clone(),
            tenant_id: old.tenant_id.clone(),
        };
        let expires_at = now_secs() + self.config.session_ttl_secs;

        self.session_provider
            .create_session(&old.user_id, expires_at, meta)
            .await
            .map_err(|e| AuthError::Provider(Box::new(e)))
    }

    /// Assert that `user` holds `role`, returning [`AuthError::Forbidden`] if not.
    ///
    /// Use this in request handlers or service methods to enforce role-based
    /// access control in one line:
    ///
    /// ```rust,ignore
    /// auth.require_role(&user, &Role::Admin)?;
    /// ```
    pub fn require_role(&self, user: &AuthUser, role: &Role) -> Result<(), AuthError> {
        if user.has_role(role) {
            Ok(())
        } else {
            Err(AuthError::Forbidden(format!(
                "role '{}' is required",
                role
            )))
        }
    }

    /// Convenience: check whether `user` holds the given `role`.
    pub fn has_role(user: &AuthUser, role: &Role) -> bool {
        user.roles.contains(role)
    }

    /// Return a reference to the underlying user provider (useful for
    /// framework adapters that need direct store access).
    pub fn user_provider(&self) -> &U {
        &self.user_provider
    }

    /// Return a reference to the underlying session provider.
    pub fn session_provider(&self) -> &S {
        &self.session_provider
    }

    /// Return a reference to the active configuration.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Fluent builder for [`AuthEngine`].
///
/// ```rust,ignore
/// let auth = AuthEngine::builder()
///     .user_provider(SqliteUserProvider::new(&pool))
///     .session_provider(SqliteSessionProvider::new(&pool))
///     .with_plugin(EmailVerificationPlugin::new(smtp_config))
///     .config(AuthConfig {
///         require_email_verification: true,
///         ..Default::default()
///     })
///     .build()?;
/// ```
pub struct AuthEngineBuilder<U, S> {
    user_provider: Option<Arc<U>>,
    session_provider: Option<Arc<S>>,
    plugins: Vec<Box<dyn AuthPlugin>>,
    config: AuthConfig,
}

impl<U, S> Default for AuthEngineBuilder<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    fn default() -> Self {
        Self {
            user_provider: None,
            session_provider: None,
            plugins: Vec::new(),
            config: AuthConfig::default(),
        }
    }
}

impl<U, S> AuthEngineBuilder<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    /// Set the user-storage backend.
    pub fn user_provider(mut self, p: U) -> Self {
        self.user_provider = Some(Arc::new(p));
        self
    }

    /// Set the session-storage backend.
    pub fn session_provider(mut self, p: S) -> Self {
        self.session_provider = Some(Arc::new(p));
        self
    }

    /// Register a plugin. Multiple plugins are invoked in registration order.
    pub fn with_plugin(mut self, plugin: impl AuthPlugin + 'static) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Override the default [`AuthConfig`].
    pub fn config(mut self, config: AuthConfig) -> Self {
        self.config = config;
        self
    }

    /// Finalise the engine.
    ///
    /// # Errors
    /// Returns [`ConfigError::MissingUserProvider`] or
    /// [`ConfigError::MissingSessionProvider`] if either provider was not set.
    pub fn build(self) -> Result<AuthEngine<U, S>, ConfigError> {
        Ok(AuthEngine {
            user_provider: self.user_provider.ok_or(ConfigError::MissingUserProvider)?,
            session_provider: self
                .session_provider
                .ok_or(ConfigError::MissingSessionProvider)?,
            plugins: self.plugins,
            config: self.config,
        })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns the current Unix timestamp in seconds.
///
/// Uses `std::time::SystemTime` on native targets (no tokio dependency).
/// Returns `0` in WASM contexts — session-time enforcement in WASM should be
/// handled server-side; `authsmith-core` is WASM-safe for types/traits only.
#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn now_secs() -> i64 {
    0
}
