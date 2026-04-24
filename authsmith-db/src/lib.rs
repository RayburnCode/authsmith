//! # authsmith-db
//!
//! SQLite and Postgres adapters implementing [`AuthProvider`] and
//! [`SessionProvider`] from `authsmith-core`.
//!
//! ## Choosing a database backend
//!
//! Selection happens at **compile time** via Cargo feature flags — there is no
//! runtime switch. Postgres is the default for production deployments; SQLite
//! is ideal for development, embedded apps, and single-binary deploys.
//!
//! | Backend  | Feature flag        | Default? | Use case                          |
//! |----------|---------------------|----------|-----------------------------------|
//! | Postgres | `postgres` (default)| ✅       | Production, multi-tenant, scaling |
//! | SQLite   | `sqlite`            |          | Dev, embedded, single-binary      |
//!
//! ### Selecting Postgres (default)
//!
//! ```toml
//! # Cargo.toml — nothing extra needed, postgres is the default
//! authsmith-db = { path = "..." }
//! ```
//!
//! ### Selecting SQLite only
//!
//! ```toml
//! # Cargo.toml
//! authsmith-db = { path = "...", default-features = false, features = ["sqlite"] }
//! ```
//!
//! ### Enabling both (e.g. integration tests)
//!
//! ```toml
//! authsmith-db = { path = "...", features = ["sqlite", "postgres"] }
//! ```
//!
//! ## How will users choose in the future?
//!
//! There are three mechanisms, each serving a different audience:
//!
//! 1. **Cargo feature flags** ← *primary* — app developers pick the adapter
//!    at compile time in their `Cargo.toml`. Zero runtime overhead.
//!
//! 2. **Environment variable** — the connection URL is passed at runtime via
//!    `DATABASE_URL` (or your own config). The feature flag determines *which*
//!    pool type you construct; the URL determines *where* it connects.
//!    ```bash
//!    DATABASE_URL=postgresql://user:pass@localhost/myapp  # postgres
//!    DATABASE_URL=sqlite://./auth.db                      # sqlite
//!    ```
//!
//! 3. **Future CLI** (`authsmith init --db postgres|sqlite`, planned for v1.0)
//!    — scaffolds migrations, generates a `.env` template, and wires everything
//!    together automatically. This is a DX convenience; it still writes feature
//!    flags into `Cargo.toml` under the hood.
//!
//! The **dashboard** never chooses the DB — it connects to an already-running
//! `authsmith-server` via HTTP. The server operator chose the backend when
//! they started the server.
//!
//! ## Usage — Postgres (default)
//!
//! ```rust,ignore
//! use authsmith_db::postgres::{PgUserStore, PgSessionStore};
//! use authsmith_db::run_postgres_migrations;
//! use authsmith_core::AuthEngine;
//! use sqlx::PgPool;
//!
//! let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
//! run_postgres_migrations(&pool).await?;
//!
//! let auth = AuthEngine::builder()
//!     .user_provider(PgUserStore::new(pool.clone()))
//!     .session_provider(PgSessionStore::new(pool))
//!     .build()?;
//! ```
//!
//! ## Usage — SQLite
//!
//! ```rust,ignore
//! use authsmith_db::sqlite::{SqliteUserStore, SqliteSessionStore};
//! use authsmith_db::run_sqlite_migrations;
//! use authsmith_core::AuthEngine;
//! use sqlx::SqlitePool;
//!
//! let pool = SqlitePool::connect("sqlite://auth.db").await?;
//! run_sqlite_migrations(&pool).await?;
//!
//! let auth = AuthEngine::builder()
//!     .user_provider(SqliteUserStore::new(pool.clone()))
//!     .session_provider(SqliteSessionStore::new(pool))
//!     .build()?;
//! ```

pub mod sqlite;
pub mod postgres;

// ── Migration helpers ─────────────────────────────────────────────────────────

/// Run the bundled SQLite migrations against `pool`.
///
/// Call this once on startup before constructing [`AuthEngine`]. Migrations are
/// idempotent — safe to call on every startup.
///
/// # Errors
/// Returns a [`sqlx::migrate::MigrateError`] if the migration fails (e.g.
/// database is locked or the schema has diverged).
#[cfg(feature = "sqlite")]
pub async fn run_sqlite_migrations(
    pool: &sqlx::SqlitePool,
) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/sqlite").run(pool).await
}

/// Run the bundled Postgres migrations against `pool`.
///
/// Call this once on startup before constructing [`AuthEngine`]. Migrations are
/// idempotent — safe to call on every startup.
///
/// # Errors
/// Returns a [`sqlx::migrate::MigrateError`] if the migration fails (e.g.
/// insufficient privileges or schema divergence).
#[cfg(feature = "postgres")]
pub async fn run_postgres_migrations(
    pool: &sqlx::PgPool,
) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/postgres").run(pool).await
} 
