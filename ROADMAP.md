<!-- @format -->

# AuthSmith — Roadmap

A modular Rust authentication and authorization framework — the Better Auth equivalent for the Rust ecosystem. Framework-agnostic, database-agnostic, and WASM-compatible.

---

## Legend

| Symbol | Meaning             |
| ------ | ------------------- |
| ✅     | Shipped             |
| 🔄     | In progress         |
| 📋     | Planned             |
| 💡     | Under consideration |

---

## v0.1 — Foundation ✅

> Core types, traits, and the `AuthEngine` builder. Everything downstream builds on this.

- ✅ `authsmith-core` — zero heavy-dep crate (WASM-safe)
  - `AuthUser`, `Role`, `Session`, `SessionMeta`, `CreateUserInput`
  - `AuthProvider`, `SessionProvider`, `AuthPlugin`, `PasswordHasher`, `TokenGenerator` traits
  - `AuthEngine<U, S>` with builder API
  - `AuthConfig` with sensible defaults
  - `AuthError` / `ConfigError` via `thiserror`
  - `AuthEngine::register()`, `create_session()`, `validate_session()`, `get_current_user()`, `logout()`, `logout_all()`, `has_role()`
- ✅ `realtor` example — end-to-end demo with in-memory providers and two plugins

---

## v0.2 — Password + Session + Axum ✅

> Make the framework usable for a real Axum application with SQLite.

- ✅ `authsmith-password` — Argon2id hashing
  - `Argon2Hasher` implementing `PasswordHasher`
  - Min/max length policy enforcement
  - Constant-time verification via the `argon2` crate
- ✅ `authsmith-session` — Secure token generation
  - `SecureTokenGenerator` — 32-byte CSPRNG tokens, base64url-encoded
  - `tokens_equal()` — constant-time comparison
  - `expiry_from_ttl()`, `now_secs()` helpers
- ✅ `authsmith-axum` — Axum integration
  - `AuthSession` extractor (401 on missing/expired session)
  - `OptionalAuthSession` extractor (guest-friendly routes)
  - `require_role()` middleware factory
  - Token extraction from `Cookie` header with `Authorization: Bearer` fallback
  - Extraction logic delegates to `authsmith_core::http` (framework-agnostic)
- 📋 `authsmith-db` SQLite adapter
  - `SqliteUserStore` implementing `AuthProvider`
  - `SqliteSessionStore` implementing `SessionProvider`
  - `sqlx::migrate!()` migration file
  - Integration tests against a real SQLite file
- 📋 Wire `authsmith-password` into `AuthEngine` — `login()` helper that hashes + verifies in one call
- 📋 Update realtor example to use SQLite + `Argon2Hasher`

---

## v0.2.5 — Framework Agnostic + Multi-tenant Foundation ✅

> Cross-cutting improvements that unblock all three pillars: framework agnosticism,
> advanced features, and flexible deployment.

- ✅ **Multi-tenancy foundation** — `tenant_id: Option<String>` on `AuthUser`, `Session`, and `CreateUserInput`
  - `Session::belongs_to_tenant()` helper for tenant-scoped session checks
  - `CreateUserInputBuilder::tenant_id()` setter
  - `None` tenant = single-tenant mode (zero breaking change for existing apps)
- ✅ **Multi-session management** — `SessionProvider::list_sessions_for_user()` required method
  - `AuthEngine::list_sessions(user_id)` convenience wrapper
  - Enables "active sessions" UIs and admin dashboards without bespoke queries
- ✅ **Framework-agnostic token extraction** — `authsmith_core::http` module (WASM-safe)
  - `extract_bearer_token(authorization: &str) -> Option<&str>`
  - `extract_cookie(cookie_header: &str, name: &str) -> Option<String>`
  - `authsmith-axum` now delegates to these instead of duplicating parsing logic
  - Any future `authsmith-actix`, `authsmith-rocket`, etc. gets the same helpers for free
- ✅ **Extended `AuthPlugin` hooks** for rate limiting and audit log readiness
  - `on_login_failed(email, reason)` — drives rate-limit counters and failed-attempt alerting
  - `on_user_banned(user)` — triggers session revocation and notification flows

---

## v0.3 — OAuth2 + Postgres 📋

> Add social login and production-grade database support.

- 📋 `authsmith-oauth` — OAuth2 / OIDC flows
  - `OAuthProvider` trait (defined ✅)
  - Google (OpenID Connect) provider
  - GitHub (OAuth2) provider
  - Discord (OAuth2) provider
  - CSRF state validation
  - Account linking — merge OAuth identity with existing email account
- 📋 `authsmith-db` Postgres adapter
  - `PgUserStore` implementing `AuthProvider`
  - `PgSessionStore` implementing `SessionProvider`
  - Mirrors SQLite adapter; only SQL dialect differs
- 📋 OAuth callback Axum handlers (example)
- 📋 `OAuthUserInfo` → `AuthUser` mapping utilities

---

## v0.4 — libp2p Peer Identity 📋

> Decentralised identity for peer-to-peer features (DSCR Express WebRTC/GossipSub).

- 📋 `authsmith-p2p` — libp2p keypair identity
  - `P2pAuthProvider` trait (defined ✅)
  - `PeerId`, `PeerChallenge`, `PeerChallengeResponse` types (defined ✅)
  - Challenge issuance + signature verification via `libp2p::identity`
  - `AuthUser::peer_id` round-trip with `SqliteUserStore`
  - Cloudflare Workers signaling layer integration notes
- 📋 Example: dual-identity login (email OR peer keypair)

---

## v0.5 — Dioxus Frontend Hooks 📋

> WASM-safe auth state hooks for Dioxus apps (DSCR Express frontend).

- 📋 `authsmith-dioxus` — Dioxus integration
  - `use_auth()` hook — reactive `Option<AuthUser>` signal
  - `use_login()` / `use_logout()` async actions
  - `<RequireAuth>` component — redirects unauthenticated users
  - `<RequireRole role=Role::Realtor>` component
  - SSR-compatible (Dioxus fullstack)
- 📋 `authsmith-core` WASM target CI check (`wasm32-unknown-unknown`)

---

## v0.6 — Two-Factor Auth 📋

- 📋 TOTP (RFC 6238) via `totp-rs`
- 📋 QR code enrollment flow
- 📋 Backup recovery codes (hashed, single-use)
- 📋 `AuthPlugin` hooks: `on_totp_enrolled`, `on_totp_verified`
- 📋 Axum extractor: `Require2FA`

---

## v0.7 — Email Verification & Password Reset 📋

- 📋 `EmailVerificationPlugin` — sends verification link on registration
- 📋 `PasswordResetPlugin` — secure reset tokens (signed, single-use, 15-min TTL)
- 📋 `lettre` integration for SMTP sending
- 📋 Token invalidation on password change (revoke all sessions)

---

## v0.8 — Audit Log + Rate Limiting 📋

- 📋 `AuditLogPlugin` — persisted auth events (login, logout, failed attempt, role change)
  - Consumes `on_login_failed` and `on_user_banned` hooks (already in `AuthPlugin`)
- 📋 `RateLimitPlugin` — configurable attempt throttling per IP and per account
  - `RateLimitStore` trait — swappable backends (in-memory, Redis)
  - Consumes `on_login_failed` hook to increment counters
- 📋 Structured `tracing` spans on all `AuthEngine` operations

---

## v0.9 — Admin Dashboard 📋

> egui/eframe native + WASM admin UI — the equivalent of Supabase Studio or Better Auth's dashboard.

- 📋 `authsmith-dashboard` — standalone binary crate
  - Connect screen (server URL + admin token)
  - **Users tab** — searchable table; ban / delete actions
  - **Sessions tab** — view all active sessions per user; one-click revoke (powered by `list_sessions_for_user`)
  - **Audit Log tab** — chronological event feed with color-coded event types
  - Async HTTP via `reqwest` + `tokio` channels (non-blocking egui event loop)
  - Native desktop build (`cargo run -p authsmith-dashboard`)
  - WASM browser build via `trunk` + `eframe::WebRunner`
- 📋 `authsmith-axum` admin feature flag
  - `GET /admin/users` — list all users
  - `POST /admin/users/{id}/ban` — ban a user (fires `on_user_banned` plugin hook)
  - `DELETE /admin/users/{id}` — delete a user + sessions
  - `GET /admin/sessions` — list active sessions
  - `DELETE /admin/sessions/{token}` — revoke a session
  - `GET /admin/audit` — recent audit events
  - Routes guarded by `Authorization: Bearer <admin-token>` middleware

---

## v0.10 — Standalone Auth Server 📋

> Package `AuthEngine` as a self-hosted HTTP service — flexible deployment without embedding.

- 📋 `authsmith-server` — standalone binary crate
  - Wraps `AuthEngine` with a minimal REST API:
    - `POST /auth/register` — create account
    - `POST /auth/login` — verify credentials + create session
    - `POST /auth/logout` — revoke session
    - `POST /auth/logout-all` — revoke all sessions for user
    - `GET  /auth/session` — validate token + return user
    - `GET  /auth/sessions` — list all sessions for current user
    - `POST /auth/refresh` — rotate session token
  - Apps communicate over HTTP instead of linking the crate — true standalone mode
  - Shares the same `authsmith-axum` route guards under the hood
  - Configured via environment variables (no hard-coded secrets)
  - Ships with Docker / `cargo install` support
- 📋 Client helper crate (`authsmith-client`) — typed HTTP client for apps talking to `authsmith-server`

---

## v0.11 — Webhooks via hooksmith-core 📋

> Forward every auth lifecycle event to any HTTP endpoint using `hooksmith-core::WebhookSender`.

- 📋 `authsmith-webhook` — `AuthPlugin` adapter crate
  - `AuthWebhookPayload` — typed, signed JSON body (`event`, `timestamp`, `data`)
  - `AuthWebhookSender` — built-in sender backed by `hooksmith_core::HttpClient`
    - Optional `RetryPolicy` with exponential back-off + jitter
    - `fail_on_error` flag — fire-and-best-effort (default) or strict delivery
  - `WebhookPlugin<S>` — generic over any `S: WebhookSender<Message = AuthWebhookPayload>`
  - Events forwarded: `user.created`, `session.created`, `session.revoked`, `auth.failed`, `user.banned`
  - Swap in any hooksmith service sender (Discord, Slack, custom) without changing AuthEngine code
- `on_login_failed` / `on_user_banned` hooks already live in `AuthPlugin` ✅ — webhook crate just consumes them
- 📋 Example: DSCR Express onboarding — `user.created` triggers welcome email + CRM record

---

## Future / Under Consideration 💡

| Idea                       | Notes                                                             |
| -------------------------- | ----------------------------------------------------------------- |
| Passkey / WebAuthn         | `webauthn-rs` integration for hardware key login                  |
| SurrealDB adapter          | `authsmith-db/surreal` — flexible schema                          |
| Session refresh / rotation | Issue a new token on each request (sliding window)                |
| Dashboard role management  | Assign / revoke roles directly from the Users tab                 |
| Dashboard OAuth status     | Show which OAuth providers are configured and their callback URLs |
| Dashboard Webhooks tab     | Configure + test webhook endpoints from the egui dashboard        |
| `authsmith-actix`          | Actix-web extractors — delegates to `authsmith_core::http`        |
| `authsmith-rocket`         | Rocket guards — delegates to `authsmith_core::http`               |
| CLI (`authsmith`)          | `cargo install authsmith` for DB migration and user management    |
| Tenant management API      | `GET /admin/tenants`, invite flows, per-tenant config             |

---

## Development Priority Order

1. **authsmith-db SQLite** — unblocks real apps; implement `list_sessions_for_user` with tenant filtering
2. **`AuthEngine::login()` full helper** — hash + verify in one call, fires `on_login_failed` on bad credentials
3. **OAuth2 providers** — social login
4. **Postgres adapter** — production databases
5. **libp2p p2p identity** — DSCR Express decentralised features
6. **Dioxus hooks** — WASM frontend
7. **2FA / email verification** — security hardening
8. **authsmith-server standalone binary** — flexible deployment without embedding

---

## Contributing

Each crate has its own `CONTRIBUTING.md` (coming soon). General rules:

- Never break WASM compatibility in `authsmith-core`
- No `unwrap()` or `expect()` in library code
- All public items must have `///` doc comments
- New features behind feature flags; `default = []` in all crates
- Unit tests inline; integration tests in `/tests`
