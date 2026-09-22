-- Support workspace-scoped and platform-wide keyset pagination orderings.
CREATE INDEX IF NOT EXISTS objects_workspace_page_idx
    ON objects (object_type, workspace, created_at_ms, COALESCE(name, ''), id);

CREATE INDEX IF NOT EXISTS objects_all_workspaces_page_idx
    ON objects (object_type, created_at_ms, COALESCE(name, ''), workspace, id);
