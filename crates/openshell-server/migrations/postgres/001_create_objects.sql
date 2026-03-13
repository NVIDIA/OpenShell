CREATE TABLE IF NOT EXISTS objects (
    object_type TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    payload BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (object_type, name)
);
