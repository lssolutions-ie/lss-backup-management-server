-- Reverses migration 030_anomaly_archive.sql.

ALTER TABLE server_tuning
    DROP COLUMN anomaly_ack_retention_days;
