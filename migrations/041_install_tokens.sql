-- Migration 041: one-time install tokens for server-assisted node deployment.
--
-- Admin generates a token on the dashboard. The token URL serves an install
-- script with embedded credentials. Token is one-time use, 24h expiry.
-- Server stores SHA-256 hash of the token (never the plaintext).

CREATE TABLE IF NOT EXISTS node_install_tokens (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash  VARCHAR(64)     NOT NULL,
    node_id     BIGINT UNSIGNED NOT NULL,
    expires_at  DATETIME        NOT NULL,
    used_at     DATETIME        NULL,
    created_by  BIGINT UNSIGNED NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_token_hash (token_hash),
    KEY idx_node_id (node_id),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);
