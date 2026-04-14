-- Migration 024: Extended job status reporting.
-- Widens last_status and adds rich result fields plus running-estimate repo size.

-- Expand allowed statuses. Using VARCHAR avoids MySQL enum-alter pain if the CLI
-- eventually emits a new value we haven't planned for.
ALTER TABLE job_snapshots MODIFY COLUMN last_status VARCHAR(32) NOT NULL DEFAULT '';

-- Add result and stats columns. All nullable or zero-defaulted for tolerant ingest.
ALTER TABLE job_snapshots
    ADD COLUMN bytes_total           BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER last_error,
    ADD COLUMN bytes_new              BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER bytes_total,
    ADD COLUMN files_total            BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER bytes_new,
    ADD COLUMN files_new              BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER files_total,
    ADD COLUMN snapshot_id            VARCHAR(64)     NOT NULL DEFAULT '' AFTER files_new,
    ADD COLUMN repo_size_observed     BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER snapshot_id,
    ADD COLUMN repo_size_estimated    BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER repo_size_observed,
    ADD COLUMN repo_size_observed_at  DATETIME NULL                       AFTER repo_size_estimated,
    ADD COLUMN error_category         VARCHAR(32)     NOT NULL DEFAULT '' AFTER repo_size_observed_at,
    ADD COLUMN repo_stats_interval_seconds INT UNSIGNED NOT NULL DEFAULT 0 AFTER error_category;
-- repo_stats_interval_seconds of 0 means inherit the global setting. Non-zero is a per-job override.
