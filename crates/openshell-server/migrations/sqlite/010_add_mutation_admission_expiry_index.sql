-- Find expired completed mutation admissions without decoding every admission,
-- across all callers for the sweeper and within one caller at capacity.
CREATE INDEX IF NOT EXISTS mutation_admission_completed_idx
    ON objects (updated_at_ms)
    WHERE object_type = 'mutation_admission_v1' AND resource_version > 1;

CREATE INDEX IF NOT EXISTS mutation_admission_bucket_completed_idx
    ON objects (workspace, updated_at_ms)
    WHERE object_type = 'mutation_admission_v1' AND resource_version > 1;
