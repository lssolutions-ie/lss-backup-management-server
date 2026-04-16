-- Migration 038: disaster recovery configuration + per-node DR state.
--
-- Server-controlled node config backup to S3 via restic. One S3 repo per
-- deployment, per-client restic password, three-state shield UI.

CREATE TABLE IF NOT EXISTS dr_config (
    id                    TINYINT UNSIGNED NOT NULL DEFAULT 1,
    s3_endpoint           VARCHAR(255)     NOT NULL DEFAULT '',
    s3_bucket             VARCHAR(255)     NOT NULL DEFAULT '',
    s3_region             VARCHAR(64)      NOT NULL DEFAULT '',
    s3_access_key_enc     TEXT             NOT NULL,
    s3_secret_key_enc     TEXT             NOT NULL,
    restic_password_enc   TEXT             NOT NULL,
    default_interval_hours INT UNSIGNED    NOT NULL DEFAULT 24,
    config_version        INT UNSIGNED     NOT NULL DEFAULT 0,
    updated_at            DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
INSERT IGNORE INTO dr_config (id, s3_access_key_enc, s3_secret_key_enc, restic_password_enc) VALUES (1, '', '', '');

ALTER TABLE nodes
    ADD COLUMN dr_enabled         TINYINT(1)      NOT NULL DEFAULT 0,
    ADD COLUMN dr_interval_hours  INT UNSIGNED     NOT NULL DEFAULT 0,
    ADD COLUMN dr_last_backup_at  DATETIME         NULL,
    ADD COLUMN dr_last_status     VARCHAR(32)      NOT NULL DEFAULT '',
    ADD COLUMN dr_last_error      TEXT             NOT NULL,
    ADD COLUMN dr_snapshot_count  INT UNSIGNED     NOT NULL DEFAULT 0,
    ADD COLUMN dr_force_run       TINYINT(1)      NOT NULL DEFAULT 0,
    ADD COLUMN dr_config_version  INT UNSIGNED     NOT NULL DEFAULT 0;
