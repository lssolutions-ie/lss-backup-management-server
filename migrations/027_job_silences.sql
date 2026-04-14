-- Migration 027: Per-(node,job) silences for alert suppression.
-- silenced_until NULL means forever.

CREATE TABLE IF NOT EXISTS job_silences (
    node_id        BIGINT UNSIGNED NOT NULL,
    job_id         VARCHAR(128)    NOT NULL,
    silenced_until DATETIME        NULL,
    reason         VARCHAR(255)    NOT NULL DEFAULT '',
    created_by     BIGINT UNSIGNED NULL,
    created_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (node_id, job_id),
    FOREIGN KEY (node_id)    REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);
