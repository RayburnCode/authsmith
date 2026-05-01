//! # authsmith-axum
//!
//! Axum extractors and middleware for AuthSmith.
//!
//! ## Pattern
//!
//! 1. Add `auth_middleware` to your router — it validates the session and
//!    inserts the resolved `AuthUser` into request extensions.
//! 2. In handlers, use `AuthSession` to extract the user (401 if absent) or
//!    `OptionalAuthSession` for guest-friendly routes.
//! 3. Use `require_role` as a layer on specific routes for role gating.
//! 4. Optionally, enable the `admin` feature and call [`admin::admin_router`]
//!    to mount the dashboard-compatible admin API.
//!
//! ```rust,ignore
//! use authsmith_axum::{auth_middleware, AuthSession, require_role};
//! use authsmith_core::Role;
//! use axum::{routing::get, Router, middleware};
//! use std::sync::Arc;
//!
//! let app = Router::new()
//!     .route("/me",    get(me_handler))
//!     .route("/admin", get(admin_handler).route_layer(
//!         middleware::from_fn(require_role(Role::Admin))
//!     ))
//!     .layer(middleware::from_fn_with_state(
//!         Arc::new(auth),
//!         auth_middleware::<MyUserStore, MySessionStore>,
//!     ));
//!
//! async fn me_handler(AuthSession(user): AuthSession) -> String {
//!     format!("Hello, {}!", user.email.unwrap_or_default())
//! }
//! ```

#[cfg(feature = "admin")]
pub mod admin;

use authsmith_core::{AuthEngine, AuthProvider, AuthUser, Role, SessionProvider};
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};
use std::sync::Arc;
use tracing::instrument;

// ── Shared state type ─────────────────────────────────────────────────────────

/// Type alias for the engine stored in Axum router state.
pub type SharedAuth<U, S> = Arc<AuthEngine<U, S>>;

// ── Cookie / header name ──────────────────────────────────────────────────────

pub const SESSION_COOKIE: &str = "authsmith_session";

// ── Token extraction ──────────────────────────────────────────────────────────

/// Extract a raw session token from the `Cookie` header or `Authorization: Bearer`.
///
/// Prefers the cookie (browser clients); falls back to Bearer (API / mobile clients).
/// Delegates to [`authsmith_core::http`] for the parsing logic so the same
/// rules apply regardless of which HTTP framework is in use.
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    // 1. Cookie header — preferred for browser clients.
    if let Some(val) = headers.get(http::header::COOKIE) {
        if let Ok(s) = val.to_str() {
            if let Some(tok) = authsmith_core::http::extract_cookie(s, SESSION_COOKIE) {
                return Some(tok);
            }
        }
    }
    // 2. Authorization: Bearer <token> — for API / mobile clients.
    if let Some(val) = headers.get(http::header::AUTHORIZATION) {
        if let Ok(s) = val.to_str() {
            if let Some(tok) = authsmith_core::http::extract_bearer_token(s) {
                return Some(tok.to_owned());
            }
        }
    }
    None
}

// ── Middleware ────────────────────────────────────────────────────────────────

/// Middleware that validates the session token and inserts the resolved
/// [`AuthUser`] into request extensions.
///
/// Routes that don't need auth can still call this; the extension simply won't
/// be present if the token is missing or invalid.
///
/// Add via `axum::middleware::from_fn_with_state(Arc::new(auth), auth_middleware::<U, S>)`.
#[instrument(skip_all)]
pub async fn auth_middleware<U, S>(
    State(auth): State<SharedAuth<U, S>>,
    mut request: Request,
    next: Next,
) -> Response
where
    U: AuthProvider + 'static,
    S: SessionProvider + 'static,
{
    if let Some(token) = extract_token(request.headers()) {
        if let Ok(user) = auth.get_current_user(&token).await {
            request.extensions_mut().insert(user);
        }
    }
    next.run(request).await
}

// ── Extractors ────────────────────────────────────────────────────────────────

/// Extractor that requires an authenticated user.
///
/// Reads the [`AuthUser`] injected by [`auth_middleware`].
/// Returns `401 Unauthorized` if the user is not present (no valid session).
pub struct AuthSession(pub AuthUser);

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(AuthSession)
            .ok_or(AuthRejection::Unauthenticated)
    }
}

/// Extractor that yields `None` when no valid session is present.
///
/// Use this for routes that render differently for guests vs logged-in users.
pub struct OptionalAuthSession(pub Option<AuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalAuthSession {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalAuthSession(parts.extensions.get::<AuthUser>().cloned()))
    }
}

// ── Role guard middleware ─────────────────────────────────────────────────────

/// Middleware that rejects requests from users who do not hold `role`.
///
/// Must be applied **after** [`auth_middleware`] in the layer stack.
///
/// ```rust,ignore
/// .route("/admin", get(handler).route_layer(
///     axum::middleware::from_fn(require_role(Role::Admin))
/// ))
/// ```
pub fn require_role(
    role: Role,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone
       + Send
       + 'static {
    move |request: Request, next: Next| {
        let role = role.clone();
        Box::pin(async move {
            match request.extensions().get::<AuthUser>() {
                Some(user) if user.roles.contains(&role) => next.run(request).await,
                Some(_) => AuthRejection::Forbidden.into_response(),
                None => AuthRejection::Unauthenticated.into_response(),
            }
        })
    }
}

// ── Rejection ─────────────────────────────────────────────────────────────────

/// HTTP rejection types returned by AuthSmith extractors and middleware.
#[derive(Debug)]
pub enum AuthRejection {
    /// No valid session was present — respond with 401.
    Unauthenticated,
    /// User is authenticated but lacks the required role — respond with 403.
    Forbidden,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            AuthRejection::Unauthenticated => {
                (StatusCode::UNAUTHORIZED, "authentication required").into_response()
            }
            AuthRejection::Forbidden => {
                (StatusCode::FORBIDDEN, "insufficient role").into_response()
            }
        }
    }
}

// ── Router integration helpers ────────────────────────────────────────────────

/// Attach auth middleware and state to a router in one call, returning a
/// fully-wired `Router<()>` ready to serve.
///
/// This is the recommended way to integrate AuthSmith into an Axum app when
/// `SharedAuth<U, S>` is the sole router state. If your app needs additional
/// state, use `Router::merge` or apply [`auth_middleware`] manually.
///
/// # Example
/// ```rust,ignore
/// use authsmith_axum::{mount_authsmith, AuthSession};
/// use axum::{routing::get, Router};
///
/// let routes = Router::new()
///     .route("/me", get(me_handler));
///
/// let app = mount_authsmith(routes, engine);
///
/// async fn me_handler(AuthSession(user): AuthSession) -> String {
///     user.email.unwrap_or_default()
/// }
/// ```
pub fn mount_authsmith<U, S>(
    routes: Router<SharedAuth<U, S>>,
    auth: AuthEngine<U, S>,
) -> Router<()>
where
    U: AuthProvider + Clone + 'static,
    S: SessionProvider + Clone + 'static,
{
    let shared = Arc::new(auth);
    routes
        .layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            auth_middleware::<U, S>,
        ))
        .with_state(shared)
}

/// Extension trait that adds a `.with_authsmith(engine)` method to
/// `Router<SharedAuth<U, S>>`.
///
/// # Example
/// ```rust,ignore
/// use authsmith_axum::{RouterExt, SharedAuth, AuthSession};
/// use axum::{routing::get, Router};
///
/// let app: Router<()> = Router::<SharedAuth<MyUsers, MySessions>>::new()
///     .route("/me", get(me_handler))
///     .with_authsmith(engine);
/// ```
pub trait RouterExt<U, S>
where
    U: AuthProvider + Clone + 'static,
    S: SessionProvider + Clone + 'static,
{
    /// Wire up auth middleware and state, consuming the router and returning
    /// a `Router<()>` ready to pass to `axum::serve`.
    fn with_authsmith(self, auth: AuthEngine<U, S>) -> Router<()>;
}

impl<U, S> RouterExt<U, S> for Router<SharedAuth<U, S>>
where
    U: AuthProvider + Clone + 'static,
    S: SessionProvider + Clone + 'static,
{
    fn with_authsmith(self, auth: AuthEngine<U, S>) -> Router<()> {
        mount_authsmith(self, auth)
    }
}

