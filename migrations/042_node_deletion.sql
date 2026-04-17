-- Migration 042: graceful node deletion with secret export.
--
-- Tracks the multi-step deletion flow: export secrets → operator confirms →
-- CLI uninstalls → node archived/removed.

ALTER TABLE nodes
    ADD COLUMN deletion_phase     VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN secrets_export_enc TEXT         NOT NULL,
    ADD COLUMN deletion_retain_data TINYINT(1) NOT NULL DEFAULT 1;
