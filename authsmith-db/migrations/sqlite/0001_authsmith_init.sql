-- AuthSmith SQLite schema — applied via `authsmith_db::run_sqlite_migrations`.
-- Idempotent: safe to run on every startup.

CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    email          TEXT UNIQUE,
    peer_id        TEXT,
    tenant_id      TEXT,
    password_hash  TEXT,
    roles          TEXT    NOT NULL DEFAULT '[]',
    metadata       TEXT    NOT NULL DEFAULT '{}',
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);

-- Speeds up tenant-scoped user lookups.
CREATE INDEX IF NOT EXISTS users_tenant_id ON users(tenant_id);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    tenant_id  TEXT,
    expires_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sessions_user_id   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_tenant_id ON sessions(tenant_id);
