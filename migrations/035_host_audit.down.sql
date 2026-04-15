-- Reverses migration 035_host_audit.sql.
-- WARNING: any audit_log rows with source='host' will fail the enum reversal —
-- delete them or keep them visible by widening the enum target.

DELETE FROM audit_log WHERE source = 'host';

ALTER TABLE audit_log
    MODIFY COLUMN source ENUM('server','node') NOT NULL;

DROP TABLE IF EXISTS host_audit_state;
