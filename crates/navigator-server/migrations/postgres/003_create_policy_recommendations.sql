-- Draft policy chunks: proposed network policy rules awaiting user approval.
CREATE TABLE IF NOT EXISTS draft_policy_chunks (
    id                  TEXT PRIMARY KEY,
    sandbox_id          TEXT NOT NULL,
    draft_version       BIGINT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    stage               TEXT NOT NULL DEFAULT 'initial',
    rule_name           TEXT NOT NULL,
    proposed_rule       BYTEA NOT NULL,
    rationale           TEXT NOT NULL,
    security_notes      TEXT NOT NULL DEFAULT '',
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    denial_refs         TEXT NOT NULL DEFAULT '[]',
    supersedes_chunk_id TEXT NOT NULL DEFAULT '',
    analysis_mode       TEXT NOT NULL DEFAULT 'mechanistic',
    created_at_ms       BIGINT NOT NULL,
    decided_at_ms       BIGINT,
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
    first_seen_ms        BIGINT NOT NULL,
    last_seen_ms         BIGINT NOT NULL,
    count                INTEGER NOT NULL DEFAULT 1,
    suppressed_count     INTEGER NOT NULL DEFAULT 0,
    total_count          INTEGER NOT NULL DEFAULT 1,
    sample_cmdlines      TEXT NOT NULL DEFAULT '[]',
    binary_sha256        TEXT NOT NULL DEFAULT '',
    persistent           BOOLEAN NOT NULL DEFAULT FALSE,
    denial_stage         TEXT NOT NULL DEFAULT 'l4_deny',
    resolved_ips         TEXT NOT NULL DEFAULT '[]',
    is_private_ip        BOOLEAN NOT NULL DEFAULT FALSE,
    l7_request_samples   TEXT NOT NULL DEFAULT '[]',
    l7_inspection_active BOOLEAN NOT NULL DEFAULT FALSE,
    status               TEXT NOT NULL DEFAULT 'new',
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_denial_summaries_sandbox
    ON denial_summaries (sandbox_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_denial_summaries_key
    ON denial_summaries (sandbox_id, host, port, binary);
