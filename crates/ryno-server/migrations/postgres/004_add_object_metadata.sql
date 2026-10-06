-- Add labels column to support Kubernetes-style object metadata
ALTER TABLE objects ADD COLUMN labels JSONB;

-- Backfill existing rows with empty labels
UPDATE objects SET labels = '{}'::jsonb WHERE labels IS NULL;
