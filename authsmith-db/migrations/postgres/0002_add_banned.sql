-- Add `banned` column to users table.
-- Using DEFAULT FALSE so this migration is safe on existing databases.
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT FALSE;
