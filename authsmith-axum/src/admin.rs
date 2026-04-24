//! Admin API routes for the AuthSmith dashboard.
//!
//! Enabled by the `admin` Cargo feature. Mount via [`admin_router`] and pass
//! the same [`SharedAuth`] you use for normal routes plus a secret admin token.
//!
//! ```rust,ignore
//! use authsmith_axum::admin::admin_router;
//! use std::sync::Arc;
//!
//! let app = Router::new()
//!     .merge(admin_router(Arc::clone(&auth), admin_token))
//!     .layer(/* normal auth middleware */);
//! ```
//!
//! All routes require `Authorization: Bearer <admin-token>`. The comparison is
//! constant-time to prevent timing attacks.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Serialize;

use authsmith_core::{AuthProvider, SessionProvider};
use authsmith_core::session::tokens_equal;

use crate::SharedAuth;

// ── State ─────────────────────────────────────────────────────────────────────

/// State threaded through all admin route handlers.
pub struct AdminState<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    pub auth: SharedAuth<U, S>,
    /// Secret bearer token required on every admin request.
    pub admin_token: String,
}

// Manual Clone: Arc<AuthEngine<U, S>> is always Clone regardless of U/S bounds.
impl<U, S> Clone for AdminState<U, S>
where
    U: AuthProvider,
    S: SessionProvider,
{
    fn clone(&self) -> Self {
        Self {
            auth: Arc::clone(&self.auth),
            admin_token: self.admin_token.clone(),
        }
    }
}

// ── Response types (mirror authsmith-dashboard/src/types.rs) ──────────────────

#[derive(Serialize)]
struct AdminUserResp {
    id: String,
    email: Option<String>,
    roles: Vec<String>,
    created_at: u64,
    banned: bool,
}

#[derive(Serialize)]
struct AdminSessionResp {
    /// First 8 characters of the token — safe to display.
    token_prefix: String,
    user_id: String,
    user_email: Option<String>,
    created_at: u64,
    expires_at: u64,
    ip: Option<String>,
}

/// Placeholder until a persistent audit-log plugin is wired in.
#[derive(Serialize)]
struct AuditEventResp {
    id: String,
    user_id: Option<String>,
    event: String,
    timestamp: u64,
    ip: Option<String>,
    metadata: Option<serde_json::Value>,
}

// ── Middleware ─────────────────────────────────────────────────────────────────

/// Validate `Authorization: Bearer <token>` against the configured admin token.
///
/// Uses constant-time comparison to prevent timing oracle attacks.
async fn admin_auth_middleware<U, S>(
    State(state): State<AdminState<U, S>>,
    request: Request,
    next: Next,
) -> Response
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    let bearer = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(authsmith_core::http::extract_bearer_token);

    match bearer {
        Some(tok) if tokens_equal(tok, &state.admin_token) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "admin token required").into_response(),
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build a [`Router`] containing all admin API routes.
///
/// Mount this alongside your normal router:
/// ```rust,ignore
/// let app = Router::new()
///     .merge(admin_router(Arc::clone(&auth), std::env::var("ADMIN_TOKEN").unwrap()))
///     /* …other routes… */;
/// ```
pub fn admin_router<U, S>(auth: SharedAuth<U, S>, admin_token: String) -> Router
where
    U: AuthProvider + Clone + 'static,
    S: SessionProvider + Clone + 'static,
{
    let state = AdminState {
        auth,
        admin_token,
    };

    Router::new()
        .route("/admin/users", get(list_users::<U, S>))
        .route("/admin/users/{id}/ban", post(ban_user::<U, S>))
        .route("/admin/users/{id}", delete(delete_user::<U, S>))
        .route("/admin/sessions", get(list_sessions::<U, S>))
        .route("/admin/sessions/{token}", delete(revoke_session::<U, S>))
        .route("/admin/audit", get(list_audit::<U, S>))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware::<U, S>,
        ))
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /admin/users` — list all registered users.
async fn list_users<U, S>(
    State(state): State<AdminState<U, S>>,
) -> Result<Json<Vec<AdminUserResp>>, StatusCode>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    let users = state
        .auth
        .list_all_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let resp = users
        .into_iter()
        .map(|u| AdminUserResp {
            id: u.id,
            email: u.email,
            roles: u.roles.iter().map(|r| r.to_string()).collect(),
            created_at: u.created_at.max(0) as u64,
            banned: u.banned,
        })
        .collect();

    Ok(Json(resp))
}

/// `POST /admin/users/{id}/ban` — set the user's `banned` flag.
///
/// Fires `on_user_banned` on all registered plugins. Returns `404` if the
/// user does not exist.
async fn ban_user<U, S>(
    State(state): State<AdminState<U, S>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    state
        .auth
        .ban_user(&id)
        .await
        .map_err(|e| match e {
            authsmith_core::AuthError::UserNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    Ok(StatusCode::OK)
}

/// `DELETE /admin/users/{id}` — permanently delete a user and all their sessions.
///
/// The `ON DELETE CASCADE` constraint on the `sessions` table ensures sessions
/// are removed atomically. Returns `404` if the user does not exist.
async fn delete_user<U, S>(
    State(state): State<AdminState<U, S>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    // Verify the user exists first so we can return 404 appropriately.
    let exists = state
        .auth
        .user_provider()
        .find_user_by_id(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some();

    if !exists {
        return Err(StatusCode::NOT_FOUND);
    }

    state
        .auth
        .user_provider()
        .delete_user(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /admin/sessions` — list all active sessions with joined user email.
async fn list_sessions<U, S>(
    State(state): State<AdminState<U, S>>,
) -> Result<Json<Vec<AdminSessionResp>>, StatusCode>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    // Fetch both in parallel logically; sequential is fine here (admin-only,
    // called rarely) and avoids complex async join machinery.
    let sessions = state
        .auth
        .list_all_sessions()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let users = state
        .auth
        .list_all_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build email lookup map.
    let email_map: HashMap<String, Option<String>> =
        users.into_iter().map(|u| (u.id, u.email)).collect();

    let resp = sessions
        .into_iter()
        .map(|s| {
            let token_prefix = s.token[..s.token.len().min(8)].to_owned();
            let user_email = email_map.get(&s.user_id).and_then(|e| e.clone());
            AdminSessionResp {
                token_prefix,
                user_id: s.user_id,
                user_email,
                created_at: s.created_at.max(0) as u64,
                expires_at: s.expires_at.max(0) as u64,
                ip: s.ip_address,
            }
        })
        .collect();

    Ok(Json(resp))
}

/// `DELETE /admin/sessions/{token_prefix}` — revoke a session by its token prefix.
///
/// Finds the first active session whose token starts with `token_prefix` and
/// revokes it. Fires `on_logout` on all registered plugins.
async fn revoke_session<U, S>(
    State(state): State<AdminState<U, S>>,
    Path(token_prefix): Path<String>,
) -> Result<StatusCode, StatusCode>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    let sessions = state
        .auth
        .list_all_sessions()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session = sessions
        .into_iter()
        .find(|s| s.token.starts_with(&token_prefix))
        .ok_or(StatusCode::NOT_FOUND)?;

    state
        .auth
        .logout(&session.token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /admin/audit` — recent audit events.
///
/// Returns an empty array until a persistent [`authsmith_core::AuthPlugin`]
/// audit-log implementation is registered. The dashboard handles empty results
/// gracefully.
async fn list_audit<U, S>(
    State(_state): State<AdminState<U, S>>,
) -> Json<Vec<AuditEventResp>>
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    // Audit events are emitted via the plugin system. A persistent audit-log
    // plugin (e.g. authsmith-notify or a custom SQLite/Postgres store) would
    // write events on each hook and expose them here. Until one is registered
    // we return an empty list so the dashboard renders cleanly.
    Json(vec![])
}
