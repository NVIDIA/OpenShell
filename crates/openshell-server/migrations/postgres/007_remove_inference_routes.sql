-- Managed inference routes were removed in favor of sandbox-scoped provider attachments.
DELETE FROM objects WHERE object_type = 'inference_route';
