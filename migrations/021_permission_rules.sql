-- Migration 021: Unified permission_rules with priority/deny/polymorphic subject+target
-- Replaces tag_permissions and user_node_overrides.

CREATE TABLE IF NOT EXISTS permission_rules (
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    priority             INT             NOT NULL DEFAULT 1000,
    effect               ENUM('allow','deny')                     NOT NULL,
    access               ENUM('view','manage')                    NOT NULL,
    subject_type         ENUM('user','user_group','user_tag')     NOT NULL,
    subject_id           BIGINT UNSIGNED NOT NULL,
    target_type          ENUM('node','node_tag')                  NOT NULL,
    target_id            BIGINT UNSIGNED NOT NULL,
    locked_by_superadmin TINYINT(1)      NOT NULL DEFAULT 0,
    created_by           BIGINT UNSIGNED NULL,
    created_at           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_priority (priority),
    KEY idx_subject (subject_type, subject_id),
    KEY idx_target (target_type, target_id)
);

-- Migrate existing tag_permissions rules: user_tag → node_tag, effect=allow, priority=1000.
INSERT INTO permission_rules (priority, effect, access, subject_type, subject_id, target_type, target_id, locked_by_superadmin, created_by, created_at)
SELECT 1000, 'allow', access, 'user_tag', user_tag_id, 'node_tag', node_tag_id, locked_by_superadmin, created_by, created_at
FROM tag_permissions;

-- Migrate existing user_node_overrides: user → node, effect=allow, priority=2000 (per-user overrides beat tag rules).
INSERT INTO permission_rules (priority, effect, access, subject_type, subject_id, target_type, target_id, locked_by_superadmin, created_by, created_at)
SELECT 2000, 'allow', access, 'user', user_id, 'node', node_id, locked_by_superadmin, created_by, created_at
FROM user_node_overrides;

-- Drop the old specialized tables.
DROP TABLE IF EXISTS tag_permissions;
DROP TABLE IF EXISTS user_node_overrides;
