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

## v0.2 — Password + Session + Axum 🔄

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
- 📋 `authsmith-db` SQLite adapter
  - `SqliteUserStore` implementing `AuthProvider`
  - `SqliteSessionStore` implementing `SessionProvider`
  - `sqlx::migrate!()` migration file
  - Integration tests against a real SQLite file
- 📋 Wire `authsmith-password` into `AuthEngine` — `login()` helper that hashes + verifies in one call
- 📋 Update realtor example to use SQLite + `Argon2Hasher`

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
- 📋 `RateLimitPlugin` — configurable attempt throttling per IP and per account
- 📋 Structured `tracing` spans on all `AuthEngine` operations

---

## Future / Under Consideration 💡

| Idea                       | Notes                                                           |
| -------------------------- | --------------------------------------------------------------- |
| Passkey / WebAuthn         | `webauthn-rs` integration for hardware key login                |
| SurrealDB adapter          | `authsmith-db/surreal` — flexible schema                        |
| Session refresh / rotation | Issue a new token on each request (sliding window)              |
| Admin API                  | REST endpoints for user management (list, ban, role assignment) |
| `authsmith-actix`          | Actix-web extractors mirroring `authsmith-axum`                 |
| CLI (`authsmith`)          | `cargo install authsmith` for DB migration and user management  |

---

## Development Priority Order

1. **authsmith-db SQLite** — unblocks real apps
2. **`AuthEngine::login()` helper** — DX improvement
3. **OAuth2 providers** — social login
4. **Postgres adapter** — production databases
5. **libp2p p2p identity** — DSCR Express decentralised features
6. **Dioxus hooks** — WASM frontend
7. **2FA / email verification** — security hardening

---

## Contributing

Each crate has its own `CONTRIBUTING.md` (coming soon). General rules:

- Never break WASM compatibility in `authsmith-core`
- No `unwrap()` or `expect()` in library code
- All public items must have `///` doc comments
- New features behind feature flags; `default = []` in all crates
- Unit tests inline; integration tests in `/tests`
