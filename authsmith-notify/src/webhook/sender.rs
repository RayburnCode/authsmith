//! Built-in [`WebhookSender`] implementation for [`AuthWebhookPayload`].

use hooksmith_core::{HttpClient, RetryPolicy, WebhookSender};

use super::event::AuthWebhookPayload;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by [`AuthWebhookSender`].
#[derive(Debug, thiserror::Error)]
pub enum AuthWebhookSenderError {
    #[error("webhook HTTP request failed: {0}")]
    Http(String),
}

// ── Sender ────────────────────────────────────────────────────────────────────

/// A [`WebhookSender`] that POSTs [`AuthWebhookPayload`] as JSON to a
/// configured HTTP endpoint using [`hooksmith_core::HttpClient`].
///
/// # Example
/// ```rust,ignore
/// let sender = AuthWebhookSender::builder()
///     .endpoint("https://yourapp.com/webhooks/auth")
///     .retry(RetryPolicy { max_attempts: 3, ..Default::default() })
///     .build();
/// ```
#[derive(Clone)]
pub struct AuthWebhookSender {
    client: HttpClient,
    endpoint: String,
    retry: Option<RetryPolicy>,
}

impl AuthWebhookSender {
    /// Start building an [`AuthWebhookSender`].
    pub fn builder() -> AuthWebhookSenderBuilder {
        AuthWebhookSenderBuilder::default()
    }
}

impl WebhookSender for AuthWebhookSender {
    type Message = AuthWebhookPayload;
    type Error = AuthWebhookSenderError;

    async fn send(&self, message: &Self::Message) -> Result<(), Self::Error> {
        match &self.retry {
            Some(policy) => {
                self.client
                    .post_json_with_retry(&self.endpoint, message, policy)
                    .await
                    .map_err(|e| AuthWebhookSenderError::Http(e.to_string()))?;
            }
            None => {
                self.client
                    .post_json(&self.endpoint, message)
                    .await
                    .map_err(|e| AuthWebhookSenderError::Http(e.to_string()))?;
            }
        }
        Ok(())
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`AuthWebhookSender`].
#[derive(Default)]
pub struct AuthWebhookSenderBuilder {
    client: Option<HttpClient>,
    endpoint: Option<String>,
    retry: Option<RetryPolicy>,
}

impl AuthWebhookSenderBuilder {
    /// The HTTPS endpoint to POST events to.
    ///
    /// # Panics
    /// Panics on `build()` if this is not set.
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into());
        self
    }

    /// Use a custom [`HttpClient`]. Defaults to `HttpClient::new()`.
    pub fn client(mut self, client: HttpClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Configure automatic retries with exponential back-off and optional jitter.
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = Some(policy);
        self
    }

    /// Finalise the builder.
    ///
    /// # Panics
    /// Panics if [`endpoint`](Self::endpoint) was not set.
    pub fn build(self) -> AuthWebhookSender {
        AuthWebhookSender {
            client: self.client.unwrap_or_default(),
            endpoint: self.endpoint.expect("AuthWebhookSenderBuilder: endpoint must be set"),
            retry: self.retry,
        }
    }
}
