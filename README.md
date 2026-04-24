<!-- @format -->

# AuthSmith

**Modular, framework-agnostic authentication and authorization for Rust.**

AuthSmith is the [Better Auth](https://www.better-auth.com) equivalent for the Rust ecosystem — a composable workspace of crates that gives you everything you need to add auth to any Rust application, from a minimal Axum API to a Dioxus WASM frontend with libp2p peer-to-peer identity.

> **Status:** Early development — `authsmith-core`, `authsmith-password`, `authsmith-session`, and `authsmith-axum` are functional. See the [Roadmap](ROADMAP.md) for what's next.

---

## Why AuthSmith?

|                   | AuthSmith                                | Roll your own            |
| ----------------- | ---------------------------------------- | ------------------------ |
| Argon2id hashing  | ✅ out of the box                        | ⚠️ easy to misconfigure  |
| Session lifecycle | ✅ CSPRNG tokens, expiry, revocation     | ⚠️ plenty of pitfalls    |
| Plugin system     | ✅ lifecycle hooks on every event        | ❌ bespoke per app       |
| Axum extractors   | ✅ `AuthSession`, `require_role()`       | ⚠️ boilerplate           |
| WASM-safe core    | ✅ no tokio, no sqlx in `authsmith-core` | ❌ usually overlooked    |
| Database-agnostic | ✅ swap SQLite ↔ Postgres ↔ SurrealDB    | ❌ hard to change later  |
| libp2p identity   | 📋 coming in v0.4                        | ❌ very hard to retrofit |

---

## Workspace layout

```
authsmith/
├── authsmith-core/        ← traits, types, AuthEngine builder (WASM-safe, zero heavy deps)
├── authsmith-password/    ← Argon2id hashing + password policy
├── authsmith-session/     ← CSPRNG token generation + expiry helpers
├── authsmith-axum/        ← Axum middleware, extractors, role guards
├── authsmith-oauth/       ← OAuth2 / OIDC provider trait (Google, GitHub — planned)
├── authsmith-p2p/         ← libp2p keypair peer identity (planned)
├── authsmith-db/
│   ├── sqlite.rs          ← SQLite adapter via sqlx (feature = "sqlite")
│   └── postgres.rs        ← Postgres adapter (planned)
└── authsmith-core/example/
    └── realtor.rs         ← full end-to-end demo with in-memory providers
```

---

## Quick start

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
authsmith-core     = { git = "https://github.com/RayburnCode/authsmith" }
authsmith-password = { git = "https://github.com/RayburnCode/authsmith" }
authsmith-session  = { git = "https://github.com/RayburnCode/authsmith" }
authsmith-axum     = { git = "https://github.com/RayburnCode/authsmith" }
```

### 1. Implement the provider traits

AuthSmith is database-agnostic — you supply the storage. The `authsmith-db` crate provides ready-made SQLite and Postgres adapters, or you can implement the two core traits yourself:

```rust
use authsmith_core::{AuthProvider, SessionProvider};

struct MyUserStore { /* your db pool */ }
struct MySessionStore { /* your db pool */ }

#[async_trait]
impl AuthProvider for MyUserStore {
    type Error = MyError;
    // create_user, find_user_by_id, find_user_by_email, update_user, delete_user
}

#[async_trait]
impl SessionProvider for MySessionStore {
    type Error = MyError;
    // create_session, get_session, revoke_session, revoke_all_sessions
}
```

### 2. Build the engine

```rust
use authsmith_core::{AuthEngine, AuthConfig, Role};
use authsmith_password::Argon2Hasher;

let auth = AuthEngine::builder()
    .user_provider(MyUserStore::new(&pool))
    .session_provider(MySessionStore::new(&pool))
    .with_plugin(AuditLogPlugin)
    .config(AuthConfig {
        session_ttl_secs: 86_400,          // 24 hours
        require_email_verification: false,
        password_min_length: 10,
        ..Default::default()
    })
    .build()?;
```

### 3. Register and log in a user

```rust
use authsmith_core::{CreateUserInput, Role, SessionMeta};
use authsmith_core::PasswordHasher;
use authsmith_password::Argon2Hasher;

let hasher = Argon2Hasher::default();
let hash = hasher.hash("correct-horse-battery-staple")?;

// Register
let user = auth.register(CreateUserInput {
    email: Some("alice@example.com".into()),
    password_hash: Some(hash),
    roles: vec![Role::Realtor],
    metadata: serde_json::json!({ "license": "CA-DRE-01234567" }),
    ..Default::default()
}).await?;

// Create session after credential verification
let session = auth.create_session(&user, SessionMeta {
    ip_address: Some(client_ip),
    user_agent: Some(user_agent),
}).await?;

println!("session token: {}", session.token);
```

### 4. Protect Axum routes

```rust
use authsmith_axum::{auth_middleware, AuthSession, require_role};
use authsmith_core::Role;
use axum::{routing::get, Router, middleware};
use std::sync::Arc;

let app = Router::new()
    .route("/me",    get(me))
    .route("/admin", get(admin).route_layer(
        middleware::from_fn(require_role(Role::Admin))
    ))
    .layer(middleware::from_fn_with_state(
        Arc::new(auth),
        auth_middleware::<MyUserStore, MySessionStore>,
    ));

// Token is read from Cookie: authsmith_session=<token>
// or Authorization: Bearer <token>
async fn me(AuthSession(user): AuthSession) -> String {
    format!("Hello, {}!", user.email.unwrap_or_default())
}

async fn admin(AuthSession(user): AuthSession) -> String {
    format!("Welcome to the admin panel, {}", user.id)
}
```

---

## Plugins

Plugins implement lifecycle hooks that fire on every auth event. Register as many as you need:

```rust
use authsmith_core::{AuthPlugin, AuthUser, Session};

struct AuditLogPlugin;

#[async_trait]
impl AuthPlugin for AuditLogPlugin {
    fn name(&self) -> &'static str { "audit-log" }

    async fn on_user_created(&self, user: &AuthUser)
        -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        tracing::info!(user_id = %user.id, "user registered");
        Ok(())
    }

    async fn on_login(&self, user: &AuthUser, session: &Session)
        -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        tracing::info!(user_id = %user.id, "login");
        Ok(())
    }

    async fn on_logout(&self, session: &Session)
        -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        tracing::info!(user_id = %session.user_id, "logout");
        Ok(())
    }
}
```

Returning an `Err` from any hook aborts the operation with `AuthError::Plugin`.

---

## Roles

Built-in roles cover common app patterns. `Custom(String)` lets any app extend without forking:

```rust
use authsmith_core::Role;

let role = Role::Custom("broker".into());

// Check in a handler
if AuthEngine::<U, S>::has_role(&user, &Role::Realtor) {
    // show realtor dashboard
}
```

---

## Security properties

- **Passwords** — Argon2id with a fresh random salt per hash (via `argon2` crate). Raw passwords are wrapped in `SecretString` and zeroed on drop.
- **Session tokens** — 32 bytes from `OsRng`, base64url-encoded (256-bit entropy). Compared with constant-time equality to prevent timing attacks.
- **No `unwrap()`** — all library code propagates errors; no panics in the happy or unhappy path.
- **WASM safety** — `authsmith-core` has zero heavy dependencies and compiles to `wasm32-unknown-unknown`.
- **Separation of concerns** — user storage and session storage are independent traits, so each can be scaled separately (e.g. Redis for sessions, Postgres for users).

---

## Run the example

```bash
git clone https://github.com/RayburnCode/authsmith
cd authsmith
cargo run --example realtor -p authsmith-core
```

Output:

```
=== DSCR Express — Realtor Auth Example ===

--- Register ---
[audit] user_created  id=usr_000001 email=Some("alice@pacificcoastrealty.com")
Registered: id=usr_000001 roles=[Realtor]

--- Login ---
[audit] login  user_id=usr_000001  token=tok_00000000…
Session token : tok_000000000000…

--- Resolve current user ---
Current user  : email=alice@pacificcoastrealty.com
Is Realtor?   : true
License #     : CA-DRE-01234567

--- Logout ---
[audit] logout  user_id=usr_000001
--- Confirm invalidation ---
Session correctly invalidated ✓
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. In brief:

| Version     | Focus                                                             |
| ----------- | ----------------------------------------------------------------- |
| **v0.1** ✅ | Core traits, `AuthEngine` builder, plugin system                  |
| **v0.2** 🔄 | Password hashing, session tokens, Axum extractors, SQLite adapter |
| **v0.3** 📋 | OAuth2 (Google, GitHub, Discord), Postgres adapter                |
| **v0.4** 📋 | libp2p peer identity                                              |
| **v0.5** 📋 | Dioxus WASM hooks                                                 |
| **v0.6** 📋 | TOTP two-factor auth                                              |
| **v0.7** 📋 | Email verification, password reset                                |
| **v0.8** 📋 | Audit log persistence, rate limiting                              |

---

## License

MIT — see [LICENSE](LICENSE).
