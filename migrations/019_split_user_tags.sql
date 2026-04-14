-- Migration 019: Split user tags from node tags
-- Previous `user_tags` junction (from migration 015) was being used ambiguously
-- for both tag permissions and user identity. This migration creates a
-- dedicated user-tag catalog and junction, fully independent of node tags.

CREATE TABLE IF NOT EXISTS user_tag_catalog (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(64) NOT NULL,
    color      VARCHAR(7)  NOT NULL DEFAULT '#206bc4',
    text_color VARCHAR(7)  NOT NULL DEFAULT '#f0f0f0',
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_tag_name (name)
);

CREATE TABLE IF NOT EXISTS user_tag_links (
    user_id     BIGINT UNSIGNED NOT NULL,
    user_tag_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, user_tag_id),
    FOREIGN KEY (user_id)     REFERENCES users(id)            ON DELETE CASCADE,
    FOREIGN KEY (user_tag_id) REFERENCES user_tag_catalog(id) ON DELETE CASCADE
);

-- Drop the old ambiguous user_tags junction (was pointing at node `tags`).
DROP TABLE IF EXISTS user_tags;
