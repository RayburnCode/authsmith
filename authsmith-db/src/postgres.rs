//! Postgres adapter — mirrors the SQLite adapter but targets [`sqlx::PgPool`].
//!
//! Enable the `postgres` feature on `authsmith-db` to activate (it is the
//! default). Call [`authsmith_db::run_postgres_migrations`] on startup.
//!
//! Uses runtime `sqlx::query_as` (no `!` macro) so no `DATABASE_URL` is
//! required at compile time — connection details are resolved at runtime via
//! the pool passed to [`PgUserStore::new`] / [`PgSessionStore::new`].

#[cfg(feature = "postgres")]
mod inner {
    use async_trait::async_trait;
    use authsmith_core::{
        AuthProvider, AuthUser, CreateUserInput, Role, Session, SessionMeta, SessionProvider,
        TokenGenerator,
    };
    use authsmith_core::session::{now_secs, SecureTokenGenerator};
    use sqlx::PgPool;
    use tracing::instrument;

    // ── Error ─────────────────────────────────────────────────────────────────

    /// Errors returned by the Postgres adapter.
    #[derive(Debug, thiserror::Error)]
    pub enum PgError {
        #[error("database error: {0}")]
        Sqlx(#[from] sqlx::Error),
        #[error("serialization error: {0}")]
        Json(#[from] serde_json::Error),
    }

    // ── Row types ─────────────────────────────────────────────────────────────

    #[derive(sqlx::FromRow)]
    struct PgUserRow {
        id: String,
        email: Option<String>,
        peer_id: Option<String>,
        tenant_id: Option<String>,
        roles: String,
        metadata: String,
        email_verified: bool,
        banned: bool,
        created_at: i64,
        updated_at: i64,
    }

    fn row_to_user(row: PgUserRow) -> Result<AuthUser, PgError> {
        let roles: Vec<Role> = serde_json::from_str(&row.roles)?;
        let metadata: serde_json::Value = serde_json::from_str(&row.metadata)?;
        Ok(AuthUser {
            id: row.id,
            email: row.email,
            peer_id: row.peer_id,
            tenant_id: row.tenant_id,
            roles,
            metadata,
            email_verified: row.email_verified,
            banned: row.banned,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    #[derive(sqlx::FromRow)]
    struct PgSessionRow {
        token: String,
        user_id: String,
        tenant_id: Option<String>,
        expires_at: i64,
        ip_address: Option<String>,
        user_agent: Option<String>,
        created_at: i64,
    }

    fn row_to_session(row: PgSessionRow) -> Session {
        Session {
            token: row.token,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            expires_at: row.expires_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            created_at: row.created_at,
        }
    }

    // ── User store ────────────────────────────────────────────────────────────

    /// Postgres-backed [`AuthProvider`].
    ///
    /// Clone-safe — wraps a [`PgPool`] which is internally `Arc`-ed.
    #[derive(Clone)]
    pub struct PgUserStore {
        pool: PgPool,
    }

    impl PgUserStore {
        /// Create a new store backed by `pool`.
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        /// Fetch the stored Argon2 password hash for the given email.
        ///
        /// Returns `None` if the user does not exist or has no password (e.g.
        /// OAuth-only accounts). Use this in your login handler to verify the
        /// raw password against the stored hash via a [`PasswordHasher`].
        ///
        /// [`PasswordHasher`]: authsmith_core::PasswordHasher
        pub async fn find_password_hash_by_email(
            &self,
            email: &str,
        ) -> Result<Option<String>, PgError> {
            let row: Option<(Option<String>,)> =
                sqlx::query_as("SELECT password_hash FROM users WHERE email = $1")
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await?;
            Ok(row.and_then(|(h,)| h))
        }
    }

    #[async_trait]
    impl AuthProvider for PgUserStore {
        type Error = PgError;

        #[instrument(skip(self, input))]
        async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error> {
            let id = ulid_str();
            let now = now_secs();
            let roles_json = serde_json::to_string(&input.roles)?;
            let metadata_json = serde_json::to_string(&input.metadata)?;

            // Use RETURNING to get the inserted row in one round-trip.
            let row = sqlx::query_as::<_, PgUserRow>(
                "INSERT INTO users \
                    (id, email, peer_id, tenant_id, password_hash, roles, metadata, email_verified, banned, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, false, false, $8, $9) \
                 RETURNING id, email, peer_id, tenant_id, roles, metadata, \
                           email_verified, banned, created_at, updated_at",
            )
            .bind(&id)
            .bind(&input.email)
            .bind(&input.peer_id)
            .bind(&input.tenant_id)
            .bind(&input.password_hash)
            .bind(&roles_json)
            .bind(&metadata_json)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

            row_to_user(row)
        }

        #[instrument(skip(self))]
        async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as::<_, PgUserRow>(
                "SELECT id, email, peer_id, tenant_id, roles, metadata, \
                        email_verified, banned, created_at, updated_at \
                 FROM users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            row.map(row_to_user).transpose()
        }

        #[instrument(skip(self))]
        async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as::<_, PgUserRow>(
                "SELECT id, email, peer_id, tenant_id, roles, metadata, \
                        email_verified, banned, created_at, updated_at \
                 FROM users WHERE email = $1",
            )
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

            row.map(row_to_user).transpose()
        }

        #[instrument(skip(self, user))]
        async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error> {
            let roles_json = serde_json::to_string(&user.roles)?;
            let metadata_json = serde_json::to_string(&user.metadata)?;
            let now = now_secs();

            sqlx::query(
                "UPDATE users \
                 SET email = $1, peer_id = $2, tenant_id = $3, roles = $4, \
                     metadata = $5, email_verified = $6, banned = $7, updated_at = $8 \
                 WHERE id = $9",
            )
            .bind(&user.email)
            .bind(&user.peer_id)
            .bind(&user.tenant_id)
            .bind(&roles_json)
            .bind(&metadata_json)
            .bind(user.email_verified)
            .bind(user.banned)
            .bind(now)
            .bind(&user.id)
            .execute(&self.pool)
            .await?;

            Ok(AuthUser { updated_at: now, ..user })
        }

        #[instrument(skip(self))]
        async fn list_users(&self) -> Result<Vec<AuthUser>, Self::Error> {
            let rows = sqlx::query_as::<_, PgUserRow>(
                "SELECT id, email, peer_id, tenant_id, roles, metadata, \
                        email_verified, banned, created_at, updated_at \
                 FROM users ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await?;

            rows.into_iter().map(row_to_user).collect()
        }

        #[instrument(skip(self))]
        async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // ── Session store ─────────────────────────────────────────────────────────

    /// Postgres-backed [`SessionProvider`].
    ///
    /// Clone-safe — wraps a [`PgPool`] which is internally `Arc`-ed.
    #[derive(Clone)]
    pub struct PgSessionStore {
        pool: PgPool,
        token_gen: SecureTokenGenerator,
    }

    impl PgSessionStore {
        /// Create a new store backed by `pool`.
        pub fn new(pool: PgPool) -> Self {
            Self {
                pool,
                token_gen: SecureTokenGenerator::default(),
            }
        }
    }

    #[async_trait]
    impl SessionProvider for PgSessionStore {
        type Error = PgError;

        #[instrument(skip(self, meta))]
        async fn create_session(
            &self,
            user_id: &str,
            expires_at: i64,
            meta: SessionMeta,
        ) -> Result<Session, Self::Error> {
            let token = self.token_gen.generate();
            let now = now_secs();

            sqlx::query(
                "INSERT INTO sessions \
                    (token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&token)
            .bind(user_id)
            .bind(&meta.tenant_id)
            .bind(expires_at)
            .bind(&meta.ip_address)
            .bind(&meta.user_agent)
            .bind(now)
            .execute(&self.pool)
            .await?;

            Ok(Session {
                token,
                user_id: user_id.to_owned(),
                tenant_id: meta.tenant_id,
                expires_at,
                ip_address: meta.ip_address,
                user_agent: meta.user_agent,
                created_at: now,
            })
        }

        #[instrument(skip(self))]
        async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error> {
            let row = sqlx::query_as::<_, PgSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions WHERE token = $1",
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(row_to_session))
        }

        #[instrument(skip(self))]
        async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
            sqlx::query("DELETE FROM sessions WHERE token = $1")
                .bind(token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        #[instrument(skip(self))]
        async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        #[instrument(skip(self))]
        async fn list_sessions_for_user(
            &self,
            user_id: &str,
        ) -> Result<Vec<Session>, Self::Error> {
            let rows = sqlx::query_as::<_, PgSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions WHERE user_id = $1 \
                 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(row_to_session).collect())
        }

        #[instrument(skip(self))]
        async fn list_all_sessions(&self) -> Result<Vec<Session>, Self::Error> {
            let rows = sqlx::query_as::<_, PgSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(row_to_session).collect())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Generates a pseudo-ULID string suitable for use as a primary key.
    ///
    /// Uses the system clock for the timestamp component and `DefaultHasher`
    /// for entropy. For production workloads consider swapping to the `ulid`
    /// crate for true lexicographic sortability and stronger randomness.
    fn ulid_str() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let rand_part: u64 = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            ts.hash(&mut h);
            h.finish()
        };
        format!("{ts:013X}{rand_part:016X}")
    }
}

#[cfg(feature = "postgres")]
pub use inner::{PgError, PgSessionStore, PgUserStore};

