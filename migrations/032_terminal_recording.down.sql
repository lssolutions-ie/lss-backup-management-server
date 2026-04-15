-- Reverses migration 032_terminal_recording.sql.
-- Note: this only drops the toggle/retention columns. The .cast files on disk
-- under terminal.sessions_dir are NOT removed — clean those up manually if you
-- want them gone:
--   rm -rf /var/lib/lss-management/sessions/

ALTER TABLE server_tuning
    DROP COLUMN terminal_recording_enabled,
    DROP COLUMN terminal_recording_retention_days;
