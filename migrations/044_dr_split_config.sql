-- Split DR config: separate server and node restic passwords + retention settings
ALTER TABLE dr_config
  ADD COLUMN server_restic_password_enc TEXT AFTER restic_password_enc,
  ADD COLUMN server_keep_last INT UNSIGNED NOT NULL DEFAULT 7,
  ADD COLUMN server_keep_daily INT UNSIGNED NOT NULL DEFAULT 30,
  ADD COLUMN node_keep_last INT UNSIGNED NOT NULL DEFAULT 7,
  ADD COLUMN node_keep_daily INT UNSIGNED NOT NULL DEFAULT 30;

-- Copy existing restic password to both server and node columns
UPDATE dr_config SET server_restic_password_enc = restic_password_enc WHERE id = 1;
