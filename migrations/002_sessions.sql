CREATE TABLE IF NOT EXISTS sessions (
  token      CHAR(64) NOT NULL PRIMARY KEY,
  user_id    BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_sessions_expires_at (expires_at)
);
