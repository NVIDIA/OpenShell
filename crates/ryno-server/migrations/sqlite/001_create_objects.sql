CREATE TABLE IF NOT EXISTS objects (
    id            TEXT PRIMARY KEY,
    object_type   TEXT NOT NULL,
    name          TEXT,
    scope         TEXT,
    version       INTEGER,
    status        TEXT,
    dedup_key     TEXT,
    hit_count     INTEGER NOT NULL DEFAULT 0,
    payload       BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS objects_name_uq
    ON objects (object_type, name)
    WHERE name IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS objects_version_uq
    ON objects (object_type, scope, version)
    WHERE scope IS NOT NULL AND version IS NOT NULL;

CREATE INDEX IF NOT EXISTS objects_scope_status_idx
    ON objects (object_type, scope, status, version)
    WHERE scope IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS objects_dedup_uq
    ON objects (object_type, scope, dedup_key)
    WHERE dedup_key IS NOT NULL;
