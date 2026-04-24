//! HTTP client that talks to the AuthSmith admin API.
//!
//! The admin API routes are provided by `authsmith-axum` when the `admin`
//! feature is enabled on your Axum app.  All requests are authenticated with a
//! long-lived admin bearer token that you configure on the server side.

use crate::types::{AdminSession, AdminUser, AuditEvent};

/// Async HTTP client for the AuthSmith admin API.
///
/// Cheaply cloneable — inner `reqwest::Client` is `Arc`-backed.
#[derive(Clone)]
pub struct AdminClient {
    base_url: String,
    admin_token: String,
    http: reqwest::Client,
}

impl AdminClient {
    /// Create a new client.
    ///
    /// `base_url` should NOT have a trailing slash, e.g. `"http://localhost:3000"`.
    /// `admin_token` is sent as `Authorization: Bearer <token>`.
    pub fn new(base_url: String, admin_token: String) -> Self {
        Self {
            base_url,
            admin_token,
            http: reqwest::Client::new(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.admin_token)
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    /// `GET /admin/users` — list all users.
    pub async fn list_users(&self) -> Result<Vec<AdminUser>, String> {
        self.http
            .get(format!("{}/admin/users", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json::<Vec<AdminUser>>()
            .await
            .map_err(|e| e.to_string())
    }

    /// `POST /admin/users/{id}/ban` — set the user's `banned` flag.
    pub async fn ban_user(&self, id: &str) -> Result<(), String> {
        self.http
            .post(format!("{}/admin/users/{}/ban", self.base_url, id))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// `DELETE /admin/users/{id}` — permanently delete a user and their sessions.
    pub async fn delete_user(&self, id: &str) -> Result<(), String> {
        self.http
            .delete(format!("{}/admin/users/{}", self.base_url, id))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    /// `GET /admin/sessions` — list all active sessions.
    pub async fn list_sessions(&self) -> Result<Vec<AdminSession>, String> {
        self.http
            .get(format!("{}/admin/sessions", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json::<Vec<AdminSession>>()
            .await
            .map_err(|e| e.to_string())
    }

    /// `DELETE /admin/sessions/{token_prefix}` — revoke a specific session.
    pub async fn revoke_session(&self, token_prefix: &str) -> Result<(), String> {
        self.http
            .delete(format!("{}/admin/sessions/{}", self.base_url, token_prefix))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    /// `GET /admin/audit` — list recent audit events (server-side limited).
    pub async fn list_audit_events(&self) -> Result<Vec<AuditEvent>, String> {
        self.http
            .get(format!("{}/admin/audit", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json::<Vec<AuditEvent>>()
            .await
            .map_err(|e| e.to_string())
    }
}
