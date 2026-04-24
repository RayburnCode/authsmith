//! Postgres adapter — mirrors the SQLite adapter but targets `sqlx::PgPool`.
//!
//! Enable the `postgres` feature on `authsmith-db` to activate.
//!
//! ## Status
//! **Planned** — the SQLite adapter ships first (v0.2). Postgres follows in v0.3.
//! The trait signatures are identical; only the SQL dialect differs.

/// Placeholder so the module compiles without the `postgres` feature.
///
/// Remove this and implement `PgUserStore` / `PgSessionStore` in v0.3.
#[allow(dead_code)]
const _POSTGRES_PLANNED: &str = "Postgres adapter coming in v0.3";
