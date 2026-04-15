-- Reverses migration 033_silent_node_alarm.sql.

ALTER TABLE server_tuning
    DROP COLUMN silent_alert_threshold_minutes;
