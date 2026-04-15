-- Reverses migration 031_audit_log.sql.
-- WARNING: drops the audit_log table — all audit history is lost. Take a backup
-- with install/lss-mgmt-backup.sh first.

ALTER TABLE nodes
    DROP COLUMN audit_ack_seq;

ALTER TABLE server_tuning
    DROP COLUMN audit_retention_days;

DROP TABLE IF EXISTS audit_log;
