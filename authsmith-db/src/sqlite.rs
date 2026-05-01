//! SQLite adapters for [`AuthProvider`] and [`SessionProvider`].
//!
//! Enable the `sqlite` feature on `authsmith-db` to activate.
//!
//! Migrations are bundled — call [`authsmith_db::run_sqlite_migrations`] on
//! startup. To apply manually, place the following in
//! `migrations/0001_authsmith_init.sql`:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS users (
//!     id             TEXT PRIMARY KEY,
//!     email          TEXT UNIQUE,
//!     peer_id        TEXT,
//!     tenant_id      TEXT,
//!     password_hash  TEXT,
//!     roles          TEXT NOT NULL DEFAULT '[]',
//!     metadata       TEXT NOT NULL DEFAULT '{}',
//!     email_verified INTEGER NOT NULL DEFAULT 0,
//!     created_at     INTEGER NOT NULL,
//!     updated_at     INTEGER NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS users_tenant_id ON users(tenant_id);
//!
//! CREATE TABLE IF NOT EXISTS sessions (
//!     token      TEXT PRIMARY KEY,
//!     user_id    TEXT NOT NULL,
//!     tenant_id  TEXT,
//!     expires_at INTEGER NOT NULL,
//!     ip_address TEXT,
//!     user_agent TEXT,
//!     created_at INTEGER NOT NULL,
//!     FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//! );
//! CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
//! CREATE INDEX IF NOT EXISTS sessions_tenant_id ON sessions(tenant_id);
//! ```

#[cfg(feature = "sqlite")]
mod inner {
    use async_trait::async_trait;
    use authsmith_core::{
        AuthProvider, AuthUser, CreateUserInput, Role, Session, SessionMeta, SessionProvider,
        TokenGenerator,
    };
    use authsmith_core::session::{now_secs, SecureTokenGenerator};
    use sqlx::SqlitePool;
    use tracing::instrument;

    // ── Error ─────────────────────────────────────────────────────────────────

    #[derive(Debug, thiserror::Error)]
    pub enum SqliteError {
        #[error("database error: {0}")]
        Sqlx(#[from] sqlx::Error),
        #[error("serialization error: {0}")]
        Json(#[from] serde_json::Error),
    }

    // ── Row types ─────────────────────────────────────────────────────────────

    /// Internal row type for user queries.
    ///
    /// Uses non-macro `sqlx::query_as` — no `DATABASE_URL` required at
    /// compile time.
    #[derive(sqlx::FromRow)]
    struct SqliteUserRow {
        id: String,
        email: Option<String>,
        peer_id: Option<String>,
        tenant_id: Option<String>,
        roles: String,
        metadata: String,
        /// SQLite stores BOOLEAN as INTEGER; sqlx decodes 0/1 → bool.
        email_verified: bool,
        banned: bool,
        created_at: i64,
        updated_at: i64,
    }

    fn row_to_user(row: SqliteUserRow) -> Result<AuthUser, SqliteError> {
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
    struct SqliteSessionRow {
        token: String,
        user_id: String,
        tenant_id: Option<String>,
        expires_at: i64,
        ip_address: Option<String>,
        user_agent: Option<String>,
        created_at: i64,
    }

    fn row_to_session(row: SqliteSessionRow) -> Session {
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

    /// SQLite-backed [`AuthProvider`].
    ///
    /// Clone-safe — wraps a [`SqlitePool`] which is internally `Arc`-ed.
    #[derive(Clone)]
    pub struct SqliteUserStore {
        pool: SqlitePool,
    }

    impl SqliteUserStore {
        pub fn new(pool: SqlitePool) -> Self {
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
        ) -> Result<Option<String>, SqliteError> {
            let row: Option<(Option<String>,)> =
                sqlx::query_as("SELECT password_hash FROM users WHERE email = ?")
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await?;
            Ok(row.and_then(|(h,)| h))
        }
    }

    #[async_trait]
    impl AuthProvider for SqliteUserStore {
        type Error = SqliteError;

        #[instrument(skip(self, input))]
        async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error> {
            let id = ulid_str();
            let now = now_secs();
            let roles_json = serde_json::to_string(&input.roles)?;
            let metadata_json = serde_json::to_string(&input.metadata)?;

            sqlx::query(
                "INSERT INTO users \
                    (id, email, peer_id, tenant_id, password_hash, roles, metadata, email_verified, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
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
            .execute(&self.pool)
            .await?;

            self.find_user_by_id(&id)
                .await?
                .ok_or_else(|| SqliteError::Sqlx(sqlx::Error::RowNotFound))
        }

        #[instrument(skip(self))]
        async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as::<_, SqliteUserRow>(
                "SELECT id, email, peer_id, tenant_id, roles, metadata, \
                        email_verified, banned, created_at, updated_at \
                 FROM users WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            row.map(row_to_user).transpose()
        }

        #[instrument(skip(self))]
        async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as::<_, SqliteUserRow>(
                "SELECT id, email, peer_id, tenant_id, roles, metadata, \
                        email_verified, banned, created_at, updated_at \
                 FROM users WHERE email = ?",
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
                 SET email = ?, peer_id = ?, tenant_id = ?, roles = ?, \
                     metadata = ?, email_verified = ?, banned = ?, updated_at = ? \
                 WHERE id = ?",
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
            let rows = sqlx::query_as::<_, SqliteUserRow>(
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
            sqlx::query("DELETE FROM users WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // ── Session store ─────────────────────────────────────────────────────────

    /// SQLite-backed [`SessionProvider`].
    ///
    /// Clone-safe — wraps a [`SqlitePool`] which is internally `Arc`-ed.
    #[derive(Clone)]
    pub struct SqliteSessionStore {
        pool: SqlitePool,
        token_gen: SecureTokenGenerator,
    }

    impl SqliteSessionStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self {
                pool,
                token_gen: SecureTokenGenerator::default(),
            }
        }
    }

    #[async_trait]
    impl SessionProvider for SqliteSessionStore {
        type Error = SqliteError;

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
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
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
            let row = sqlx::query_as::<_, SqliteSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions WHERE token = ?",
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(row_to_session))
        }

        #[instrument(skip(self))]
        async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
            sqlx::query("DELETE FROM sessions WHERE token = ?")
                .bind(token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        #[instrument(skip(self))]
        async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
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
            let rows = sqlx::query_as::<_, SqliteSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions WHERE user_id = ? \
                 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(row_to_session).collect())
        }

        #[instrument(skip(self))]
        async fn list_all_sessions(&self) -> Result<Vec<Session>, Self::Error> {
            let rows = sqlx::query_as::<_, SqliteSessionRow>(
                "SELECT token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at \
                 FROM sessions \
                 ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(row_to_session).collect())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

#[cfg(feature = "sqlite")]
pub use inner::{SqliteError, SqliteSessionStore, SqliteUserStore};

