//! Webhook notification plugin for AuthSmith.
//!
//! Enable with `features = ["webhook"]`.
//!
//! Forwards auth lifecycle events as typed JSON to any HTTP endpoint.
//!
//! ```rust,ignore
//! use authsmith_notify::webhook::{WebhookPlugin, AuthWebhookSender};
//!
//! let sender = AuthWebhookSender::builder()
//!     .endpoint("https://yourapp.com/webhooks/auth")
//!     .build();
//!
//! let auth = AuthEngine::builder()
//!     .user_provider(store)
//!     .session_provider(sessions)
//!     .with_plugin(WebhookPlugin::new(sender))
//!     .build()?;
//! ```

pub mod event;
pub mod plugin;
pub mod sender;

pub use event::{AuthEvent, AuthWebhookPayload};
pub use plugin::WebhookPlugin;
pub use sender::{AuthWebhookSender, AuthWebhookSenderBuilder, AuthWebhookSenderError};
