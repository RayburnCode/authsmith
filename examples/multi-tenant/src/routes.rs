use authsmith_axum::auth_middleware;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::{
    handlers::{list_tenant_users, login, me, register},
    state::AppState,
    store::{MemSessionStore, MemUserStore},
};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/tenant/users", get(list_tenant_users))
        // auth_middleware runs on all routes; handlers decide whether to require
        // AuthSession (401 if absent) or OptionalAuthSession (None if absent).
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.auth),
            auth_middleware::<MemUserStore, MemSessionStore>,
        ))
        .with_state(state)
}
