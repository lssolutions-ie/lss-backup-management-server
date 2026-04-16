-- Reverses migration 036_snapshot_id_tracking.sql.
-- Forensic snapshot pairs on existing anomaly rows are lost.

ALTER TABLE job_anomalies
    DROP COLUMN curr_snapshot_id,
    DROP COLUMN prev_snapshot_id;

ALTER TABLE job_snapshots
    DROP COLUMN snapshot_ids;
