-- Migration 039: remote CLI version tracking + update scheduling.

ALTER TABLE nodes
    ADD COLUMN cli_version        VARCHAR(32)  NOT NULL DEFAULT '',
    ADD COLUMN cli_update_pending TINYINT(1)   NOT NULL DEFAULT 0;

-- Cache the latest known CLI version from GitHub tags check.
ALTER TABLE server_tuning
    ADD COLUMN latest_cli_version VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN latest_cli_version_checked_at DATETIME NULL;
