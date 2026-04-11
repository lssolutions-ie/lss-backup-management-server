ALTER TABLE node_reports
  ADD COLUMN report_type VARCHAR(32) NOT NULL DEFAULT 'post_run' AFTER received_at;
