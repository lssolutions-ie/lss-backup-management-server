-- Store release notes from GitHub for display on the updates page
ALTER TABLE server_tuning ADD COLUMN latest_server_release_notes TEXT AFTER latest_server_version;
