-- Reverses migration 039_cli_version_update.sql.

ALTER TABLE server_tuning
    DROP COLUMN latest_cli_version_checked_at,
    DROP COLUMN latest_cli_version;

ALTER TABLE nodes
    DROP COLUMN cli_update_pending,
    DROP COLUMN cli_version;
