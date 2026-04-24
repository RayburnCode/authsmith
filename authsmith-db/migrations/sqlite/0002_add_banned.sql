-- Add `banned` column to users table.
-- SQLite does not support adding NOT NULL columns without a DEFAULT to existing
-- tables, so we include DEFAULT 0 (false) to make this migration safe on both
-- new and existing databases.
ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
