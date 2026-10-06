-- Add labels column to support Kubernetes-style object metadata
ALTER TABLE objects ADD COLUMN labels TEXT;

-- Backfill existing rows with empty labels
UPDATE objects SET labels = '{}' WHERE labels IS NULL;
