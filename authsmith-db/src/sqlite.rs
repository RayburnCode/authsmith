//! SQLite adapters for [`AuthProvider`] and [`SessionProvider`].
//!
//! Enable the `sqlite` feature on `authsmith-db` to activate.
//!
//! ## Required migrations
//!
//! Place the following in `migrations/0001_authsmith.sql` and run via
//! `sqlx::migrate!()`:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS users (
//!     id             TEXT PRIMARY KEY,
//!     email          TEXT UNIQUE,
//!     peer_id        TEXT,
//!     password_hash  TEXT,
//!     roles          TEXT NOT NULL DEFAULT '[]',
//!     metadata       TEXT NOT NULL DEFAULT '{}',
//!     email_verified INTEGER NOT NULL DEFAULT 0,
//!     created_at     INTEGER NOT NULL,
//!     updated_at     INTEGER NOT NULL
//! );
//!
//! CREATE TABLE IF NOT EXISTS sessions (
//!     token      TEXT PRIMARY KEY,
//!     user_id    TEXT NOT NULL,
//!     expires_at INTEGER NOT NULL,
//!     ip_address TEXT,
//!     user_agent TEXT,
//!     created_at INTEGER NOT NULL,
//!     FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
//! );
//! CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
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

    // ── User store ────────────────────────────────────────────────────────────

    /// SQLite-backed [`AuthProvider`].
    #[derive(Clone)]
    pub struct SqliteUserStore {
        pool: SqlitePool,
    }

    impl SqliteUserStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }
    }

    struct UserRow {
        id: String,
        email: Option<String>,
        peer_id: Option<String>,
        roles: String,
        metadata: String,
        email_verified: i64,
        created_at: i64,
        updated_at: i64,
    }

    fn row_to_user(row: UserRow) -> Result<AuthUser, SqliteError> {
        let roles: Vec<Role> = serde_json::from_str(&row.roles)?;
        let metadata: serde_json::Value = serde_json::from_str(&row.metadata)?;
        Ok(AuthUser {
            id: row.id,
            email: row.email,
            peer_id: row.peer_id,
            roles,
            metadata,
            email_verified: row.email_verified != 0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
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

            sqlx::query!(
                r#"INSERT INTO users (id, email, peer_id, roles, metadata, email_verified, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 0, ?, ?)"#,
                id, input.email, input.peer_id, roles_json, metadata_json, now, now
            )
            .execute(&self.pool)
            .await?;

            self.find_user_by_id(&id)
                .await?
                .ok_or_else(|| SqliteError::Sqlx(sqlx::Error::RowNotFound))
        }

        #[instrument(skip(self))]
        async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as!(
                UserRow,
                "SELECT id, email, peer_id, roles, metadata, email_verified, created_at, updated_at
                 FROM users WHERE id = ?",
                id
            )
            .fetch_optional(&self.pool)
            .await?;

            row.map(row_to_user).transpose()
        }

        #[instrument(skip(self))]
        async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
            let row = sqlx::query_as!(
                UserRow,
                "SELECT id, email, peer_id, roles, metadata, email_verified, created_at, updated_at
                 FROM users WHERE email = ?",
                email
            )
            .fetch_optional(&self.pool)
            .await?;

            row.map(row_to_user).transpose()
        }

        #[instrument(skip(self, user))]
        async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error> {
            let roles_json = serde_json::to_string(&user.roles)?;
            let metadata_json = serde_json::to_string(&user.metadata)?;
            let now = now_secs();
            let verified = user.email_verified as i64;

            sqlx::query!(
                r#"UPDATE users SET email = ?, peer_id = ?, roles = ?, metadata = ?,
                   email_verified = ?, updated_at = ? WHERE id = ?"#,
                user.email, user.peer_id, roles_json, metadata_json, verified, now, user.id
            )
            .execute(&self.pool)
            .await?;

            Ok(AuthUser { updated_at: now, ..user })
        }

        #[instrument(skip(self))]
        async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
            sqlx::query!("DELETE FROM users WHERE id = ?", id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
    }

    // ── Session store ─────────────────────────────────────────────────────────

    /// SQLite-backed [`SessionProvider`].
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

            sqlx::query!(
                r#"INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)"#,
                token, user_id, expires_at, meta.ip_address, meta.user_agent, now
            )
            .execute(&self.pool)
            .await?;

            Ok(Session {
                token,
                user_id: user_id.to_owned(),
                expires_at,
                ip_address: meta.ip_address,
                user_agent: meta.user_agent,
                created_at: now,
            })
        }

        #[instrument(skip(self))]
        async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error> {
            let row = sqlx::query!(
                "SELECT token, user_id, expires_at, ip_address, user_agent, created_at
                 FROM sessions WHERE token = ?",
                token
            )
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|r| Session {
                token: r.token,
                user_id: r.user_id,
                expires_at: r.expires_at,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                created_at: r.created_at,
            }))
        }

        #[instrument(skip(self))]
        async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
            sqlx::query!("DELETE FROM sessions WHERE token = ?", token)
                .execute(&self.pool)
                .await?;
            Ok(())
        }

        #[instrument(skip(self))]
        async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
            sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
                .execute(&self.pool)
                .await?;
            Ok(())
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

    // Re-export for convenience.
    pub use self::{SqliteSessionStore, SqliteUserStore};
}

#[cfg(feature = "sqlite")]
pub use inner::{SqliteError, SqliteSessionStore, SqliteUserStore};

