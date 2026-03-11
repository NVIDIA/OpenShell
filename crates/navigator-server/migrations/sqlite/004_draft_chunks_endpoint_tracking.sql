-- Add denormalized endpoint columns and hit tracking to draft_policy_chunks.
-- These support DB-level dedup (unique index on sandbox_id + host + port for
-- active chunks) and first/last-seen counters.

ALTER TABLE draft_policy_chunks ADD COLUMN host TEXT NOT NULL DEFAULT '';
ALTER TABLE draft_policy_chunks ADD COLUMN port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE draft_policy_chunks ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE draft_policy_chunks ADD COLUMN first_seen_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE draft_policy_chunks ADD COLUMN last_seen_ms INTEGER NOT NULL DEFAULT 0;

-- Backfill first/last_seen_ms from created_at_ms for existing rows.
UPDATE draft_policy_chunks
SET first_seen_ms = created_at_ms,
    last_seen_ms  = created_at_ms
WHERE first_seen_ms = 0;

-- Unique index: only one pending/approved chunk per endpoint per sandbox.
-- Rejected and superseded chunks are excluded so they don't block new proposals.
CREATE UNIQUE INDEX IF NOT EXISTS idx_draft_chunks_endpoint
    ON draft_policy_chunks (sandbox_id, host, port)
    WHERE status IN ('pending', 'approved');
