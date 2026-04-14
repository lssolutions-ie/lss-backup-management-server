-- Migration 025: Server tuning (single-row global settings table).

CREATE TABLE IF NOT EXISTS server_tuning (
    id                               TINYINT UNSIGNED NOT NULL DEFAULT 1,
    repo_stats_interval_seconds      INT UNSIGNED NOT NULL DEFAULT 86400,
    repo_stats_timeout_seconds       INT UNSIGNED NOT NULL DEFAULT 300,
    retention_raw_days               INT UNSIGNED NOT NULL DEFAULT 7,
    retention_post_run_days          INT UNSIGNED NOT NULL DEFAULT 30,
    offline_threshold_minutes        INT UNSIGNED NOT NULL DEFAULT 10,
    offline_check_interval_minutes   INT UNSIGNED NOT NULL DEFAULT 5,
    default_silence_seconds          INT UNSIGNED NOT NULL DEFAULT 3600,
    updated_at                       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

INSERT IGNORE INTO server_tuning (id) VALUES (1);
