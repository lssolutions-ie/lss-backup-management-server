-- Reverses migration 040_update_settings.sql.

ALTER TABLE server_tuning
    DROP COLUMN latest_server_version_checked_at,
    DROP COLUMN latest_server_version,
    DROP COLUMN update_check_interval_minutes;
