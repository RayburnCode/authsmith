-- AuthSmith Postgres schema — applied via `authsmith_db::run_postgres_migrations`.
-- Idempotent: safe to run on every startup.

CREATE TABLE IF NOT EXISTS users (
    id             TEXT    PRIMARY KEY,
    email          TEXT    UNIQUE,
    peer_id        TEXT,
    tenant_id      TEXT,
    password_hash  TEXT,
    roles          TEXT    NOT NULL DEFAULT '[]',
    metadata       TEXT    NOT NULL DEFAULT '{}',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     BIGINT  NOT NULL,
    updated_at     BIGINT  NOT NULL
);

-- Speeds up tenant-scoped user lookups.
CREATE INDEX IF NOT EXISTS users_tenant_id ON users(tenant_id);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT   PRIMARY KEY,
    user_id    TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  TEXT,
    expires_at BIGINT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_id   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_tenant_id ON sessions(tenant_id);
