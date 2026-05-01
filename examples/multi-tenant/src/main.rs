//! # multi-tenant — AuthSmith Multi-Tenant Example
//!
//! Shows how to run a single AuthSmith engine that serves multiple independent
//! tenants (organisations, workspaces, etc.) from the same Axum server.
//!
//! ## Concept
//!
//! AuthSmith has first-class multi-tenancy through two fields:
//!
//! - **`AuthUser::tenant_id`** — every user is optionally scoped to a tenant.
//! - **`Session::tenant_id`** — every session mirrors the tenant of its owner,
//!   or can be set independently via [`SessionMeta::tenant_id`].
//!
//! This lets you share one database (and one engine) while keeping tenants
//! isolated in application logic. The schema already has an index on
//! `tenant_id` in the DB adapters for efficient per-tenant queries.
//!
//! ## Architecture used here
//!
//! ```
//! Request
//!   │
//!   ├─ X-Tenant-ID: acme       (header set by client or reverse proxy)
//!   │
//!   ├─ tenant_middleware        → extracts & validates tenant slug
//!   ├─ auth_middleware          → validates session token → AuthUser
//!   │
//!   └─ Handler
//!        ├─ TenantId extractor  → the tenant from the header
//!        └─ AuthSession         → the authenticated user
//!             └─ guard: user.tenant_id == request tenant_id
//! ```
//!
//! In production the tenant could also come from a subdomain
//! (`acme.yourapp.com`) parsed by a layer before auth runs.
//!
//! ## Run
//!
//! ```sh
//! cargo run -p multi-tenant
//! ```
//!
//! ## Try the API
//!
//! ```sh
//! # Register a user in "acme" tenant
//! curl -s -X POST http://localhost:3000/register \
//!   -H 'Content-Type: application/json' \
//!   -H 'X-Tenant-ID: acme' \
//!   -d '{"email":"bob@acme.com","password":"hunter2-correct-horse"}' | jq
//!
//! # Register another user in "globex" tenant
//! curl -s -X POST http://localhost:3000/register \
//!   -H 'Content-Type: application/json' \
//!   -H 'X-Tenant-ID: globex' \
//!   -d '{"email":"carol@globex.com","password":"hunter2-correct-horse"}' | jq
//!
//! # Login as bob (acme)
//! TOKEN=$(curl -s -X POST http://localhost:3000/login \
//!   -H 'Content-Type: application/json' \
//!   -H 'X-Tenant-ID: acme' \
//!   -d '{"email":"bob@acme.com","password":"hunter2-correct-horse"}' | jq -r .token)
//!
//! # /me returns Bob's profile + his tenant
//! curl -s http://localhost:3000/me \
//!   -H "Authorization: Bearer $TOKEN" \
//!   -H 'X-Tenant-ID: acme' | jq
//!
//! # Cross-tenant access is blocked — Bob's token in the globex context returns 403
//! curl -s http://localhost:3000/me \
//!   -H "Authorization: Bearer $TOKEN" \
//!   -H 'X-Tenant-ID: globex'
//! ```

mod handlers;
mod routes;
mod state;
mod store;
mod tenant;
mod types;

use authsmith_core::{AuthConfig, AuthEngine};
use authsmith_password::Argon2Hasher;
use state::AppState;
use store::{MemSessionStore, MemUserStore};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // One engine, many tenants.
    let auth = AuthEngine::builder()
        .user_provider(MemUserStore::default())
        .session_provider(MemSessionStore::default())
        .config(AuthConfig::default())
        .build()
        .expect("engine build failed");

    let state = AppState { auth: Arc::new(auth), hasher: Arc::new(Argon2Hasher::default()) };

    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("multi-tenant server listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
