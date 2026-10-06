-- Add resource_version column for optimistic concurrency control
ALTER TABLE objects ADD COLUMN resource_version INTEGER NOT NULL DEFAULT 1;

-- Backfill existing rows with resource_version = 1
-- (DEFAULT clause handles this automatically for existing rows in SQLite)
