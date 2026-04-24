//! Shared types that mirror the JSON shapes the admin API returns.
//!
//! These are **client-side** representations — they are intentionally minimal
//! so the dashboard compiles without depending on `authsmith-core`.

use serde::{Deserialize, Serialize};

/// A user record as returned by `GET /admin/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub email: Option<String>,
    /// Display names of the user's roles, e.g. `["admin", "realtor"]`.
    pub roles: Vec<String>,
    /// Unix timestamp (seconds) of account creation.
    pub created_at: u64,
    pub banned: bool,
}

/// An active session as returned by `GET /admin/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    /// First 8 characters of the opaque token — safe to display.
    pub token_prefix: String,
    pub user_id: String,
    pub user_email: Option<String>,
    /// Unix timestamp (seconds).
    pub created_at: u64,
    /// Unix timestamp (seconds).
    pub expires_at: u64,
    pub ip: Option<String>,
}

/// A single audit-log event as returned by `GET /admin/audit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub user_id: Option<String>,
    /// Machine-readable event name, e.g. `"user.login"`, `"session.revoked"`.
    pub event: String,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    pub ip: Option<String>,
    /// Optional arbitrary metadata stored with the event.
    pub metadata: Option<serde_json::Value>,
}
