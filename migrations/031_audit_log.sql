-- Migration 031: Unified audit log for server-originated and node-originated events.

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ts              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source          ENUM('server','node') NOT NULL,
    source_node_id  BIGINT UNSIGNED NULL,
    source_seq      BIGINT UNSIGNED NULL,
    user_id         BIGINT UNSIGNED NULL,
    username        VARCHAR(64)     NOT NULL DEFAULT '',
    ip              VARCHAR(45)     NOT NULL DEFAULT '',
    category        VARCHAR(64)     NOT NULL,
    severity        ENUM('info','warn','critical') NOT NULL DEFAULT 'info',
    actor           VARCHAR(128)    NOT NULL DEFAULT '',
    action          VARCHAR(64)     NOT NULL DEFAULT '',
    entity_type     VARCHAR(32)     NOT NULL DEFAULT '',
    entity_id       VARCHAR(128)    NOT NULL DEFAULT '',
    message         VARCHAR(500)    NOT NULL DEFAULT '',
    details_json    JSON            NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_node_seq (source_node_id, source_seq),
    KEY idx_ts (ts),
    KEY idx_source_ts (source, ts),
    KEY idx_node_ts (source_node_id, ts),
    KEY idx_category (category),
    FOREIGN KEY (source_node_id) REFERENCES nodes(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Retention for audit rows. 0 = keep forever. Default forever.
ALTER TABLE server_tuning
    ADD COLUMN audit_retention_days INT UNSIGNED NOT NULL DEFAULT 0;

-- Track the last seq we acked per node so the ingest path can look it up cheaply.
-- Stored on nodes so we don't need another small table.
ALTER TABLE nodes
    ADD COLUMN audit_ack_seq BIGINT UNSIGNED NOT NULL DEFAULT 0;
