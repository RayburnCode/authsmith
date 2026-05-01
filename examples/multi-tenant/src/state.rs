use authsmith_axum::SharedAuth;
use authsmith_password::Argon2Hasher;
use axum::extract::FromRef;
use std::sync::Arc;

use crate::store::{MemSessionStore, MemUserStore};

#[derive(Clone)]
pub struct AppState {
    pub auth: SharedAuth<MemUserStore, MemSessionStore>,
    pub hasher: Arc<Argon2Hasher>,
}

impl FromRef<AppState> for SharedAuth<MemUserStore, MemSessionStore> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.auth)
    }
}
