ALTER TABLE job_snapshots
  ADD COLUMN config_json JSON NULL AFTER schedule_description;
