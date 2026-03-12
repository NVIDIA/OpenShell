-- Expand the endpoint dedup index to cover all active statuses.
--
-- Draft chunks now follow a toggle model:
--   pending -> approved | rejected  (initial decision)
--   approved <-> rejected            (toggle)
--
-- One row per (sandbox_id, host, port) — rejected chunks stay in the index
-- so new denials bump hit_count instead of creating duplicate pending rows.

-- First, deduplicate any existing rejected rows that would violate the new
-- wider unique index. Keep the row with the highest hit_count (tie-break by
-- most recent last_seen_ms), delete the rest.
DELETE FROM draft_policy_chunks
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM (
        -- For each (sandbox_id, host, port) pick the best row across all
        -- statuses that will be covered by the new index.
        SELECT rowid,
               ROW_NUMBER() OVER (
                   PARTITION BY sandbox_id, host, port
                   ORDER BY
                       CASE status WHEN 'approved' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
                       hit_count DESC,
                       last_seen_ms DESC
               ) AS rn
        FROM draft_policy_chunks
        WHERE status IN ('pending', 'approved', 'rejected')
    )
    WHERE rn = 1
)
AND status IN ('pending', 'approved', 'rejected');

DROP INDEX IF EXISTS idx_draft_chunks_endpoint;

CREATE UNIQUE INDEX idx_draft_chunks_endpoint
    ON draft_policy_chunks (sandbox_id, host, port)
    WHERE status IN ('pending', 'approved', 'rejected');
