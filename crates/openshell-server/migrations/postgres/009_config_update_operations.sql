CREATE TABLE IF NOT EXISTS sandbox_config_fences (
    sandbox_id TEXT PRIMARY KEY REFERENCES objects(id) ON DELETE CASCADE
);

ALTER TABLE objects
    ADD COLUMN IF NOT EXISTS next_attempt_at_ms BIGINT;

UPDATE objects
SET next_attempt_at_ms = updated_at_ms
WHERE object_type = 'config_update_operation'
  AND next_attempt_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS objects_type_status_due_idx
    ON objects (object_type, status, next_attempt_at_ms, id);
