CREATE TABLE IF NOT EXISTS users (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('superadmin','user') NOT NULL DEFAULT 'user',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS client_groups (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(128) NOT NULL UNIQUE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_client_group_access (
  user_id         BIGINT UNSIGNED NOT NULL,
  client_group_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, client_group_id),
  FOREIGN KEY (user_id)         REFERENCES users(id)         ON DELETE CASCADE,
  FOREIGN KEY (client_group_id) REFERENCES client_groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nodes (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uid             VARCHAR(128) NOT NULL UNIQUE,
  name            VARCHAR(128) NOT NULL,
  client_group_id BIGINT UNSIGNED NOT NULL,
  psk_encrypted   TEXT NOT NULL,
  first_seen_at   DATETIME,
  last_seen_at    DATETIME,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_group_id) REFERENCES client_groups(id)
);

CREATE TABLE IF NOT EXISTS node_reports (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id      BIGINT UNSIGNED NOT NULL,
  reported_at  DATETIME NOT NULL,
  received_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  payload_json MEDIUMTEXT NOT NULL,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
  INDEX idx_node_reports_node_id_reported_at (node_id, reported_at DESC)
);

CREATE TABLE IF NOT EXISTS job_snapshots (
  id                        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id                   BIGINT UNSIGNED NOT NULL,
  job_id                    VARCHAR(128) NOT NULL,
  job_name                  VARCHAR(255) NOT NULL,
  program                   VARCHAR(32) NOT NULL,
  enabled                   TINYINT(1) NOT NULL DEFAULT 1,
  last_status               VARCHAR(32) NOT NULL DEFAULT '',
  last_run_at               DATETIME,
  last_run_duration_seconds INT NOT NULL DEFAULT 0,
  last_error                TEXT,
  next_run_at               DATETIME,
  schedule_description      VARCHAR(255) NOT NULL DEFAULT '',
  updated_at                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_node_job (node_id, job_id),
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
