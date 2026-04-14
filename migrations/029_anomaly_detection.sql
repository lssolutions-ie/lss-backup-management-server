-- Migration 029: Anomaly detection for security (deletion / corruption signals).

-- Snapshot count tracked per job (CLI v2.2.6+ will send this in result.snapshot_count).
ALTER TABLE job_snapshots
    ADD COLUMN snapshot_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER repo_size_observed_at;

-- Audit log of every detected anomaly. Used for forensics and the Security tab.
CREATE TABLE IF NOT EXISTS job_anomalies (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node_id         BIGINT UNSIGNED NOT NULL,
    job_id          VARCHAR(128)    NOT NULL,
    detected_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    anomaly_type    ENUM('snapshot_drop','files_drop','bytes_drop') NOT NULL,
    prev_value      BIGINT          NOT NULL,
    curr_value      BIGINT          NOT NULL,
    delta_value     BIGINT          NOT NULL,
    delta_pct       DECIMAL(6,2)    NOT NULL DEFAULT 0,
    snapshot_id     VARCHAR(64)     NOT NULL DEFAULT '',
    acknowledged    TINYINT(1)      NOT NULL DEFAULT 0,
    acknowledged_by BIGINT UNSIGNED NULL,
    acknowledged_at DATETIME        NULL,
    PRIMARY KEY (id),
    KEY idx_node_job (node_id, job_id),
    KEY idx_detected (detected_at),
    KEY idx_unacked (acknowledged, detected_at),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Tunable thresholds in server_tuning. Defaults conservative.
ALTER TABLE server_tuning
    ADD COLUMN anomaly_snapshot_drop_threshold INT UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN anomaly_files_drop_pct          INT UNSIGNED NOT NULL DEFAULT 5,
    ADD COLUMN anomaly_files_drop_min          INT UNSIGNED NOT NULL DEFAULT 10,
    ADD COLUMN anomaly_bytes_drop_pct          INT UNSIGNED NOT NULL DEFAULT 10,
    ADD COLUMN anomaly_bytes_drop_min_mb       INT UNSIGNED NOT NULL DEFAULT 100;
