-- Migration 030: Anomaly acknowledged-row retention.
-- Acked anomalies older than this disappear from the live /anomalies page
-- but remain in the job_anomalies table forever and show on /anomalies/archive.

ALTER TABLE server_tuning
    ADD COLUMN anomaly_ack_retention_days INT UNSIGNED NOT NULL DEFAULT 30;
