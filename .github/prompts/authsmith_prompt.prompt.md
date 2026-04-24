---
name: authsmith_prompt
description: Describe when to use this prompt
---

<!-- @format -->

<!-- Tip: Use /create-prompt in chat to generate content with agent assistance -->

<!-- @format -->

# AuthSmith — Rust Authentication Crate Development

## Project Overview

You are helping build **AuthSmith**, a modular, reusable Rust authentication
crate workspace designed to be a TypeScript Better Auth equivalent for the
Rust ecosystem. It is framework-agnostic, database-agnostic, and
WASM-compatible for use with Dioxus frontends.

The primary consumer app is **DSCR Express** — a real estate investing
platform for investors, realtors, and mortgage lenders built with
Rust + Dioxus. AuthSmith must support both traditional server auth AND
libp2p peer-to-peer identity for decentralized features.

---

## Workspace Structure

authsmith/
├── Cargo.toml ← workspace root
├── crates/
│ ├── authsmith-core/ ← traits, types, errors (zero heavy deps)
│ ├── authsmith-session/ ← session creation, validation, revocation
│ ├── authsmith-password/ ← argon2 hashing, password policy
│ ├── authsmith-oauth/ ← OAuth2/OIDC flows
│ ├── authsmith-p2p/ ← libp2p keypair peer identity
│ ├── authsmith-axum/ ← Axum extractors, middleware, guards
│ ├── authsmith-dioxus/ ← Dioxus hooks and auth state (WASM)
│ └── authsmith-db/
│ ├── sqlite/ ← SQLite adapter via sqlx
│ ├── postgres/ ← Postgres adapter via sqlx
│ └── surreal/ ← SurrealDB adapter
└── examples/
├── dscr-express/ ← primary real-world consumer
└── basic-axum/ ← minimal reference example

---

## Coding Standards & Conventions

### Rust Style

- Edition: Rust 2021
- Async runtime: Tokio
- All async traits use `async_trait` crate until native async traits stabilize
- Errors: use `thiserror` for library errors, `anyhow` acceptable in examples only
- Serialization: `serde` with `Serialize + Deserialize` on all public types
- Use `Arc<T>` for shared state, never `Rc<T>`
- Prefer `impl Trait` in function args, concrete types in structs
- No `unwrap()` or `expect()` in library code — always propagate errors
- Document every public item with `///` doc comments including examples
- All public types derive `Debug, Clone`

### Architecture Rules

- `authsmith-core` must have ZERO heavy dependencies (no sqlx, no axum, no tokio)
- `authsmith-core` must compile to WASM (wasm32-unknown-unknown target)
- All integrations (DB, framework) are feature-flagged and opt-in
- Plugin system uses the `AuthPlugin` trait — never hard-code behavior
- Builder pattern for `AuthEngine` construction
- Adapter pattern for all database implementations

### Feature Flags Convention

[features]
default = ["password", "session"]
password = ["argon2", "authsmith-password"]
oauth = ["oauth2", "reqwest", "authsmith-oauth"]
passkey = ["webauthn-rs"]
p2p = ["libp2p", "authsmith-p2p"]
sqlite = ["sqlx/sqlite"]
postgres = ["sqlx/postgres"]
surreal = ["surrealdb"]
axum = ["authsmith-axum"]
dioxus = ["authsmith-dioxus"]
email = ["lettre"]
two-factor = ["totp-rs"]

---

## Core Types (authsmith-core)

### AuthUser

pub struct AuthUser {
pub id: String, // ulid preferred over uuid
pub email: Option<String>,
pub peer_id: Option<String>, // libp2p PeerId as string
pub roles: Vec<Role>,
pub metadata: serde_json::Value, // app-specific (license #, NMLS, etc.)
pub email_verified: bool,
pub created_at: i64, // unix timestamp
pub updated_at: i64,
}

### Role

pub enum Role {
Investor,
Realtor,
Lender,
Admin,
Custom(String), // all apps can extend without forking
}

### Session

pub struct Session {
pub token: String, // cryptographically random, 32 bytes
pub user_id: String,
pub expires_at: i64,
pub ip_address: Option<String>,
pub user_agent: Option<String>,
pub created_at: i64,
}

### Core Traits

- `AuthProvider` — CRUD for users (async, generic error)
- `SessionProvider` — create/validate/revoke sessions (async, generic error)
- `AuthPlugin` — lifecycle hooks: on_user_created, on_login, on_logout
- `PasswordHasher` — hash/verify abstraction over argon2 or bcrypt
- `TokenGenerator` — pluggable secure token generation

---

## AuthEngine Builder API

// Target ergonomic usage — mirror Better Auth's DX but in Rust
let auth = AuthEngine::builder()
.user_provider(SqliteUserProvider::new(&pool))
.session_provider(SqliteSessionProvider::new(&pool))
.with_plugin(EmailVerification::new(smtp_config))
.with_plugin(RoleVerification::new(allowed_roles))
.config(AuthConfig {
session_ttl: Duration::hours(24),
require_email_verification: true,
password_min_length: 10,
..Default::default()
})
.build()?;

---

## DSCR Express Context (primary consumer app)

- Users have roles: Investor, Realtor, Lender
- Realtors need role verification (license badge system)
- Lenders need NMLS number stored in metadata
- App uses both traditional login AND libp2p peer identity
- Signaling layer uses Cloudflare Workers (free tier)
- Real-time features: WebRTC 1:1 chat, libp2p GossipSub listing board
- Database: SQLite in development, Postgres in production
- Frontend: Dioxus (WASM), so authsmith-core must be WASM-safe

---

## Development Priorities (in order)

1. authsmith-core — traits + types, WASM-safe, zero heavy deps
2. authsmith-password — argon2 hashing + password policy
3. authsmith-session — session lifecycle with SQLite backend
4. authsmith-axum — Axum extractors + route guards
5. authsmith-db/sqlite — SQLite AuthProvider implementation
6. authsmith-oauth — OAuth2 (Google, GitHub providers first)
7. authsmith-p2p — libp2p keypair identity integration
8. authsmith-dioxus — WASM hooks for frontend auth state
9. authsmith-db/postgres — Postgres adapter
10. authsmith-db/surreal — SurrealDB adapter (future)

---

## What To Always Do

- Ask which crate we are working in before generating code
- Respect feature flag boundaries — never import axum in core
- Use `ulid` crate for ID generation (not uuid)
- Sessions tokens: `rand::thread_rng` + base64url encoded, 32 bytes minimum
- Always implement `Display` and `std::error::Error` for all error types
- Write unit tests inline (`#[cfg(test)]`) for all business logic
- Write integration tests in `/tests` folder for DB adapters
- Use `sqlx::migrate!` macro for database migrations
- Keep authsmith-core dependencies to only:
  serde, serde_json, thiserror, async-trait, chrono (or time)

## What To Never Do

- Never use `unwrap()` or `expect()` in any crate/\* code
- Never import framework crates (axum, actix, dioxus) into authsmith-core
- Never hard-code secrets or connection strings
- Never store raw passwords — always hash before persistence
- Never roll custom crypto — use established crates only
- Never make authsmith-core depend on tokio directly
- Never break WASM compatibility in authsmith-core
