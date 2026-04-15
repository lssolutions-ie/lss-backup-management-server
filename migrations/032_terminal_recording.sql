-- Migration 032: terminal session recording.

ALTER TABLE server_tuning
    ADD COLUMN terminal_recording_enabled       TINYINT(1)      NOT NULL DEFAULT 1,
    ADD COLUMN terminal_recording_retention_days INT UNSIGNED   NOT NULL DEFAULT 30;
