-- Migration 035: extend audit_log.source enum to include 'host' for events
-- collected from the management server's own systemd journal (sshd, sudo,
-- lss-backup-server.service lifecycle).

ALTER TABLE audit_log
    MODIFY COLUMN source ENUM('server','node','host') NOT NULL;

-- Track journal cursor per source so the host-audit worker only re-reads new
-- events between ticks. One row, set to '' on first run.
CREATE TABLE IF NOT EXISTS host_audit_state (
    id            TINYINT UNSIGNED NOT NULL DEFAULT 1,
    journal_cursor VARCHAR(255)    NOT NULL DEFAULT '',
    updated_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
INSERT IGNORE INTO host_audit_state (id, journal_cursor) VALUES (1, '');
