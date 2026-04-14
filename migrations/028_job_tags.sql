-- Migration 028: Job tags for priority labels and filtering.

CREATE TABLE IF NOT EXISTS job_tag_catalog (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(64)  NOT NULL,
    color      VARCHAR(7)   NOT NULL DEFAULT '#206bc4',
    text_color VARCHAR(7)   NOT NULL DEFAULT '#f0f0f0',
    priority   TINYINT UNSIGNED NOT NULL DEFAULT 2,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_job_tag_name (name)
);
-- priority scale: 0=low, 1=normal, 2=high, 3=critical. Used for alert weighting.

CREATE TABLE IF NOT EXISTS job_tag_links (
    node_id    BIGINT UNSIGNED NOT NULL,
    job_id     VARCHAR(128)    NOT NULL,
    job_tag_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (node_id, job_id, job_tag_id),
    FOREIGN KEY (node_id)    REFERENCES nodes(id)           ON DELETE CASCADE,
    FOREIGN KEY (job_tag_id) REFERENCES job_tag_catalog(id) ON DELETE CASCADE
);
