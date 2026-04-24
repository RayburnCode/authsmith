//! # authsmith-db
//!
//! SQLite and Postgres adapters implementing [`AuthProvider`] and [`SessionProvider`]
//! from `authsmith-core`.
//!
//! Enable the `sqlite` or `postgres` feature flag to activate the relevant adapter.
//!
//! ## Usage (SQLite)
//!
//! ```rust,ignore
//! use authsmith_db::sqlite::{SqliteUserStore, SqliteSessionStore};
//! use authsmith_core::AuthEngine;
//! use sqlx::SqlitePool;
//!
//! let pool = SqlitePool::connect("sqlite://auth.db").await?;
//! sqlx::migrate!("./migrations").run(&pool).await?;
//!
//! let auth = AuthEngine::builder()
//!     .user_provider(SqliteUserStore::new(pool.clone()))
//!     .session_provider(SqliteSessionStore::new(pool))
//!     .build()?;
//! ```

pub mod sqlite;
pub mod postgres;
