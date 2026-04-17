-- Reverses migration 042_node_deletion.sql.

ALTER TABLE nodes
    DROP COLUMN deletion_retain_data,
    DROP COLUMN secrets_export_enc,
    DROP COLUMN deletion_phase;
