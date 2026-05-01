//! # authsmith
//!
//! Single-crate entry point for the AuthSmith authentication framework.
//!
//! Rather than adding five separate crates to your `Cargo.toml`, enable the
//! features you need and import everything from `authsmith::`.
//!
//! ```toml
//! [dependencies]
//! authsmith = { version = "0.1", features = ["axum", "postgres", "password", "smtp"] }
//! ```
//!
//! ## Feature flags
//!
//! | Feature    | What it enables                                           |
//! |------------|-----------------------------------------------------------|
//! | *(none)*   | `authsmith-core` — all types, traits, `AuthEngine`       |
//! | `axum`     | Axum middleware, extractors, `mount_authsmith`, `RouterExt` |
//! | `postgres` | `PgUserStore`, `PgSessionStore`, `pg_setup`               |
//! | `sqlite`   | `SqliteUserStore`, `SqliteSessionStore`, `sqlite_setup`   |
//! | `password` | `Argon2Hasher`                                            |
//! | `smtp`     | `EmailPlugin`, `SmtpEmailSender`, `DefaultEmailTemplates` |
//! | `webhook`  | `WebhookPlugin`, `AuthWebhookSender`                      |
//! | `macros`   | `#[require_role]`, `derive(AuthProvider)`                 |
//! | `full`     | All stable features                                       |
//!
//! ## Quick start (Postgres + Axum)
//!
//! ```rust,ignore
//! use authsmith::{
//!     AuthConfig, AuthEngine,
//!     db::{pg_setup},
//!     axum::{mount_authsmith, AuthSession, RouterExt},
//!     password::Argon2Hasher,
//! };
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
//!
//!     let auth = pg_setup(&pool).await?
//!         .config(AuthConfig::from_env())
//!         .build()?;
//!
//!     let app = axum::Router::new()
//!         .route("/me", axum::routing::get(me_handler))
//!         .with_authsmith(auth);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!     Ok(())
//! }
//!
//! async fn me_handler(AuthSession(user): AuthSession) -> String {
//!     user.email.unwrap_or_default()
//! }
//! ```

// ── Core (always available) ───────────────────────────────────────────────────

pub use authsmith_core::*;

// ── Axum integration ──────────────────────────────────────────────────────────

#[cfg(feature = "axum")]
pub mod axum {
    //! Axum middleware, extractors, and router helpers.
    pub use authsmith_axum::*;
}

// ── Database adapters ─────────────────────────────────────────────────────────

#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod db {
    //! Database adapters and convenience setup functions.
    pub use authsmith_db::*;
}

// ── Password hashing ──────────────────────────────────────────────────────────

#[cfg(feature = "password")]
pub mod password {
    //! Argon2id password hashing.
    pub use authsmith_password::*;
}

// ── Notification plugins ──────────────────────────────────────────────────────

#[cfg(any(feature = "smtp", feature = "webhook"))]
pub mod notify {
    //! Email and webhook notification plugins.
    pub use authsmith_notify::*;
}

// ── OAuth (planned) ───────────────────────────────────────────────────────────

#[cfg(feature = "oauth")]
pub mod oauth {
    //! OAuth 2.0 provider integrations (Google, GitHub, Discord, …).
    pub use authsmith_oauth::*;
}

// ── P2P / libp2p (planned) ────────────────────────────────────────────────────

#[cfg(feature = "p2p")]
pub mod p2p {
    //! Peer-to-peer identity via libp2p.
    pub use authsmith_p2p::*;
}

// ── Proc-macros ───────────────────────────────────────────────────────────────

#[cfg(feature = "macros")]
pub use authsmith_macros::*;
