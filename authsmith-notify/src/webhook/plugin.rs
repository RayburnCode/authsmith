//! [`WebhookPlugin`] — an [`AuthPlugin`] that forwards every auth lifecycle
//! event to a [`WebhookSender`].

use async_trait::async_trait;
use hooksmith_core::WebhookSender;
use tracing::{error, instrument};

use authsmith_core::{AuthPlugin, AuthUser, Session};

use super::event::{AuthEvent, AuthWebhookPayload};

// ── WebhookPlugin ─────────────────────────────────────────────────────────────

/// An [`AuthPlugin`] that forwards auth lifecycle events to a
/// [`WebhookSender<Message = AuthWebhookPayload>`].
///
/// Generic over the sender so the type is zero-cost and test-friendly.
///
/// # Error handling
///
/// By default, webhook delivery failures are **logged** but do **not** abort
/// the auth operation (fire-and-best-effort). Set
/// [`fail_on_error`](WebhookPlugin::fail_on_error) to `true` if you need
/// strict delivery guarantees.
pub struct WebhookPlugin<S>
where
    S: WebhookSender<Message = AuthWebhookPayload>,
{
    sender: S,
    /// If `true`, a send failure causes the plugin hook to return an error.
    /// Defaults to `false` (fire-and-best-effort).
    pub fail_on_error: bool,
}

impl<S> WebhookPlugin<S>
where
    S: WebhookSender<Message = AuthWebhookPayload>,
{
    /// Create a new plugin that forwards events through `sender`.
    ///
    /// Delivery failures are logged but do **not** abort auth operations.
    pub fn new(sender: S) -> Self {
        Self { sender, fail_on_error: false }
    }

    /// Create a plugin that **fails** auth operations when webhook delivery fails.
    pub fn with_fail_on_error(sender: S) -> Self {
        Self { sender, fail_on_error: true }
    }

    async fn dispatch(
        &self,
        event: AuthEvent<'_>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = event.into_payload();
        match self.sender.send(&payload).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.fail_on_error {
                    Err(Box::new(WebhookPluginError(e.to_string())))
                } else {
                    error!(error = %e, "authsmith-notify/webhook: delivery failed (fire-and-best-effort)");
                    Ok(())
                }
            }
        }
    }
}

// ── AuthPlugin impl ───────────────────────────────────────────────────────────

#[async_trait]
impl<S> AuthPlugin for WebhookPlugin<S>
where
    S: WebhookSender<Message = AuthWebhookPayload> + Send + Sync,
    S::Error: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "authsmith-notify/webhook"
    }

    #[instrument(skip_all, fields(plugin = "authsmith-notify/webhook", event = "user.created"))]
    async fn on_user_created(
        &self,
        user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.dispatch(AuthEvent::UserCreated(user)).await
    }

    #[instrument(skip_all, fields(plugin = "authsmith-notify/webhook", event = "session.created"))]
    async fn on_login(
        &self,
        user: &AuthUser,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.dispatch(AuthEvent::SessionCreated { user, session }).await
    }

    #[instrument(skip_all, fields(plugin = "authsmith-notify/webhook", event = "session.revoked"))]
    async fn on_logout(
        &self,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.dispatch(AuthEvent::SessionRevoked(session)).await
    }
}

// ── Error wrapper ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("webhook delivery failed: {0}")]
struct WebhookPluginError(String);
