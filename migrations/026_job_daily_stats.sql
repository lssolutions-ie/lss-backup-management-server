-- Migration 026: Daily aggregate stats per (node, job) for long-term history.

CREATE TABLE IF NOT EXISTS job_daily_stats (
    node_id            BIGINT UNSIGNED NOT NULL,
    job_id             VARCHAR(128)    NOT NULL,
    day                DATE            NOT NULL,
    runs               INT UNSIGNED    NOT NULL DEFAULT 0,
    successes          INT UNSIGNED    NOT NULL DEFAULT 0,
    warnings           INT UNSIGNED    NOT NULL DEFAULT 0,
    failures           INT UNSIGNED    NOT NULL DEFAULT 0,
    skipped            INT UNSIGNED    NOT NULL DEFAULT 0,
    total_duration_s   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_new_sum      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    worst_error_cat    VARCHAR(32)     NOT NULL DEFAULT '',
    PRIMARY KEY (node_id, job_id, day),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
