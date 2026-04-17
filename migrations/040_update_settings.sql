-- Migration 040: configurable update check interval + server version tracking.

ALTER TABLE server_tuning
    ADD COLUMN update_check_interval_minutes INT UNSIGNED NOT NULL DEFAULT 30,
    ADD COLUMN latest_server_version         VARCHAR(32)  NOT NULL DEFAULT '',
    ADD COLUMN latest_server_version_checked_at DATETIME  NULL;
