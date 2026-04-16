-- Reverses migration 038_disaster_recovery.sql.
-- WARNING: drops all DR configuration and per-node DR state.

ALTER TABLE nodes
    DROP COLUMN dr_config_version,
    DROP COLUMN dr_force_run,
    DROP COLUMN dr_snapshot_count,
    DROP COLUMN dr_last_error,
    DROP COLUMN dr_last_status,
    DROP COLUMN dr_last_backup_at,
    DROP COLUMN dr_interval_hours,
    DROP COLUMN dr_enabled;

DROP TABLE IF EXISTS dr_config;
