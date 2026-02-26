CREATE TABLE IF NOT EXISTS sandbox_policies (
    id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    policy_payload BYTEA NOT NULL,
    policy_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    load_error TEXT,
    created_at_ms BIGINT NOT NULL,
    loaded_at_ms BIGINT,
    UNIQUE (sandbox_id, version)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_policies_lookup
    ON sandbox_policies (sandbox_id, version DESC);
