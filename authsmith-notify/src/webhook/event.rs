//! Webhook event types — the JSON payload posted to your endpoint.

use authsmith_core::{AuthUser, Session};
use serde::{Deserialize, Serialize};

// ── Payload ───────────────────────────────────────────────────────────────────

/// The JSON body POSTed to your webhook endpoint on every auth event.
///
/// ```json
/// {
///   "event": "session.created",
///   "timestamp": 1714000000,
///   "data": { "user_id": "01J...", "session_token_prefix": "aB3x..." }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthWebhookPayload {
    /// Machine-readable event name (e.g. `"user.created"`, `"session.revoked"`).
    pub event: &'static str,
    /// Unix timestamp (seconds) at the moment the event was emitted.
    pub timestamp: u64,
    /// Event-specific data as a JSON value.
    pub data: serde_json::Value,
}

// ── AuthEvent builders ────────────────────────────────────────────────────────

/// All auth lifecycle events that can be forwarded to a webhook endpoint.
#[derive(Debug, Clone)]
pub enum AuthEvent<'a> {
    /// A new user account was created.
    UserCreated(&'a AuthUser),
    /// A session was created after successful authentication.
    SessionCreated { user: &'a AuthUser, session: &'a Session },
    /// A session was revoked (logout or admin action).
    SessionRevoked(&'a Session),
}

impl<'a> AuthEvent<'a> {
    /// The stable string identifier used in the `"event"` field.
    pub fn name(&self) -> &'static str {
        match self {
            AuthEvent::UserCreated(_) => "user.created",
            AuthEvent::SessionCreated { .. } => "session.created",
            AuthEvent::SessionRevoked(_) => "session.revoked",
        }
    }

    /// Serialize the event into a ready-to-send [`AuthWebhookPayload`].
    pub fn into_payload(self) -> AuthWebhookPayload {
        let data = match &self {
            AuthEvent::UserCreated(user) => serde_json::json!({
                "user_id": user.id,
                "email": user.email,
                "roles": user.roles.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            }),
            AuthEvent::SessionCreated { user, session } => serde_json::json!({
                "user_id": user.id,
                "email": user.email,
                // Only expose first 8 chars — enough for correlation, never the full token.
                "session_token_prefix": &session.token[..session.token.len().min(8)],
                "expires_at": session.expires_at,
                "ip_address": session.ip_address,
            }),
            AuthEvent::SessionRevoked(session) => serde_json::json!({
                "user_id": session.user_id,
                "session_token_prefix": &session.token[..session.token.len().min(8)],
            }),
        };

        AuthWebhookPayload {
            event: self.name(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            data,
        }
    }
}
