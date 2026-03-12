-- Draft policy chunks: proposed network policy rules awaiting user approval.
--
-- One row per (sandbox_id, host, port, binary). The toggle model allows:
--   pending -> approved | rejected   (initial decision)
--   approved <-> rejected            (toggle via approve/revoke)
--
-- Upserts bump hit_count / last_seen_ms when the same denial recurs.
CREATE TABLE IF NOT EXISTS draft_policy_chunks (
    id              TEXT PRIMARY KEY,
    sandbox_id      TEXT NOT NULL,
    draft_version   INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    rule_name       TEXT NOT NULL,
    proposed_rule   BLOB NOT NULL,
    rationale       TEXT NOT NULL DEFAULT '',
    security_notes  TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.0,
    host            TEXT NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 0,
    binary          TEXT NOT NULL DEFAULT '',
    hit_count       INTEGER NOT NULL DEFAULT 1,
    first_seen_ms   INTEGER NOT NULL,
    last_seen_ms    INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    decided_at_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_draft_chunks_sandbox
    ON draft_policy_chunks (sandbox_id, status);

-- Only one active chunk per (sandbox, endpoint, binary). Covers all three
-- statuses so rejected chunks block duplicate proposals until re-approved.
CREATE UNIQUE INDEX IF NOT EXISTS idx_draft_chunks_endpoint
    ON draft_policy_chunks (sandbox_id, host, port, binary)
    WHERE status IN ('pending', 'approved', 'rejected');
