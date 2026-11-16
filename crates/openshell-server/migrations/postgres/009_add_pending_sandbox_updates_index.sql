CREATE INDEX IF NOT EXISTS sandbox_pending_updates_idx
    ON objects (object_type, id)
    WHERE object_type = 'sandbox_image_state' AND status = 'pending';
