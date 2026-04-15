-- Reverses migration 034_anomaly_resolution_note.sql.
-- Note: drops any captured resolution notes — those are gone for good.

ALTER TABLE job_anomalies
    DROP COLUMN resolution_note;
