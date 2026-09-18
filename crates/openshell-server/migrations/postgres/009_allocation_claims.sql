CREATE TABLE allocation_claims (
    target TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    runtime_generation TEXT NOT NULL
);
CREATE INDEX allocation_claims_sandbox_idx ON allocation_claims (sandbox_id);
