-- Draft policy chunks: proposed network policy rules awaiting user approval.
CREATE TABLE IF NOT EXISTS draft_policy_chunks (
    id                  TEXT PRIMARY KEY,
    sandbox_id          TEXT NOT NULL,
    draft_version       INTEGER NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    stage               TEXT NOT NULL DEFAULT 'initial',
    rule_name           TEXT NOT NULL,
    proposed_rule       BLOB NOT NULL,
    rationale           TEXT NOT NULL,
    security_notes      TEXT NOT NULL DEFAULT '',
    confidence          REAL NOT NULL DEFAULT 0.0,
    denial_refs         TEXT NOT NULL DEFAULT '[]',
    supersedes_chunk_id TEXT NOT NULL DEFAULT '',
    analysis_mode       TEXT NOT NULL DEFAULT 'mechanistic',
    created_at_ms       INTEGER NOT NULL,
    decided_at_ms       INTEGER,
    decided_by          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_draft_chunks_sandbox
    ON draft_policy_chunks (sandbox_id, status);

-- Denial summaries: aggregated denial data from sandbox.
CREATE TABLE IF NOT EXISTS denial_summaries (
    id                   TEXT PRIMARY KEY,
    sandbox_id           TEXT NOT NULL,
    host                 TEXT NOT NULL,
    port                 INTEGER NOT NULL,
    binary               TEXT NOT NULL,
    ancestors            TEXT NOT NULL DEFAULT '[]',
    deny_reason          TEXT NOT NULL,
    first_seen_ms        INTEGER NOT NULL,
    last_seen_ms         INTEGER NOT NULL,
    count                INTEGER NOT NULL DEFAULT 1,
    suppressed_count     INTEGER NOT NULL DEFAULT 0,
    total_count          INTEGER NOT NULL DEFAULT 1,
    sample_cmdlines      TEXT NOT NULL DEFAULT '[]',
    binary_sha256        TEXT NOT NULL DEFAULT '',
    persistent           INTEGER NOT NULL DEFAULT 0,
    denial_stage         TEXT NOT NULL DEFAULT 'l4_deny',
    resolved_ips         TEXT NOT NULL DEFAULT '[]',
    is_private_ip        INTEGER NOT NULL DEFAULT 0,
    l7_request_samples   TEXT NOT NULL DEFAULT '[]',
    l7_inspection_active INTEGER NOT NULL DEFAULT 0,
    status               TEXT NOT NULL DEFAULT 'new',
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_denial_summaries_sandbox
    ON denial_summaries (sandbox_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_denial_summaries_key
    ON denial_summaries (sandbox_id, host, port, binary);
