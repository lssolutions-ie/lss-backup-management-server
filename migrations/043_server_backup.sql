-- Server auto-backup settings
ALTER TABLE server_tuning
  ADD COLUMN server_backup_enabled TINYINT(1) NOT NULL DEFAULT 1,
  ADD COLUMN server_backup_interval_hours INT UNSIGNED NOT NULL DEFAULT 24,
  ADD COLUMN server_backup_last_at DATETIME DEFAULT NULL,
  ADD COLUMN server_backup_last_status VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN server_backup_last_error TEXT;
