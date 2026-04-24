//! # authsmith-notify
//!
//! Outbound notification plugins for AuthSmith.
//!
//! ## Features
//!
//! - **`smtp`** — SMTP email integration via `lettre`. Provides [`EmailPlugin`],
//!   [`EmailSender`], and pluggable [`EmailTemplates`]. See the [`email`] module.
//! - **`webhook`** — Forwards auth lifecycle events as JSON to any HTTP endpoint.
//!   Provides [`WebhookPlugin`] and [`AuthWebhookSender`]. See the [`webhook`] module.
//!
//! Enable only what you need:
//!
//! ```toml
//! authsmith-notify = { version = "0.1", features = ["smtp", "webhook"] }
//! ```

#[cfg(feature = "smtp")]
pub mod email;

#[cfg(feature = "webhook")]
pub mod webhook;
