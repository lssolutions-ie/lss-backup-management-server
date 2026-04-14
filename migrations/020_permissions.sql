-- Migration 020: Permission system
-- Layered model: Client (top filter) → Role (capabilities) → Tag-to-Tag (visibility & access)
-- Plus user groups (inherit tags) and per-user per-node overrides.

-- Rule: "Users with user_tag_id X can see/manage nodes with node_tag_id Y"
CREATE TABLE IF NOT EXISTS tag_permissions (
    user_tag_id          BIGINT UNSIGNED NOT NULL,
    node_tag_id          BIGINT UNSIGNED NOT NULL,
    access               ENUM('view','manage') NOT NULL DEFAULT 'view',
    locked_by_superadmin TINYINT(1)      NOT NULL DEFAULT 0,
    created_by           BIGINT UNSIGNED NULL,
    created_at           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_tag_id, node_tag_id),
    FOREIGN KEY (user_tag_id) REFERENCES user_tag_catalog(id) ON DELETE CASCADE,
    FOREIGN KEY (node_tag_id) REFERENCES tags(id)             ON DELETE CASCADE,
    FOREIGN KEY (created_by)  REFERENCES users(id)            ON DELETE SET NULL
);

-- Team / group of users, scoped to one client.
CREATE TABLE IF NOT EXISTS user_groups (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name            VARCHAR(128)    NOT NULL,
    client_group_id BIGINT UNSIGNED NOT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_group_name_client (name, client_group_id),
    FOREIGN KEY (client_group_id) REFERENCES client_groups(id) ON DELETE CASCADE
);

-- Membership, with a lead flag for team leaders.
CREATE TABLE IF NOT EXISTS user_group_members (
    user_group_id BIGINT UNSIGNED NOT NULL,
    user_id       BIGINT UNSIGNED NOT NULL,
    is_lead       TINYINT(1)      NOT NULL DEFAULT 0,
    PRIMARY KEY (user_group_id, user_id),
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)       REFERENCES users(id)       ON DELETE CASCADE
);

-- Tags attached to a group — every member inherits these tags.
CREATE TABLE IF NOT EXISTS user_group_tags (
    user_group_id BIGINT UNSIGNED NOT NULL,
    user_tag_id   BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_group_id, user_tag_id),
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id)      ON DELETE CASCADE,
    FOREIGN KEY (user_tag_id)   REFERENCES user_tag_catalog(id) ON DELETE CASCADE
);

-- Per-user per-node override. Stacks additively with tag-based access (max wins).
CREATE TABLE IF NOT EXISTS user_node_overrides (
    user_id              BIGINT UNSIGNED NOT NULL,
    node_id              BIGINT UNSIGNED NOT NULL,
    access               ENUM('view','manage') NOT NULL,
    locked_by_superadmin TINYINT(1)      NOT NULL DEFAULT 0,
    created_by           BIGINT UNSIGNED NULL,
    created_at           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, node_id),
    FOREIGN KEY (user_id)    REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id)    REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);
