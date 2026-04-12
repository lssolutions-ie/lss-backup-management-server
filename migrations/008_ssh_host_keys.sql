CREATE TABLE IF NOT EXISTS ssh_host_keys (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  host       VARCHAR(255)    NOT NULL,
  key_type   VARCHAR(50)     NOT NULL,
  key_data   TEXT            NOT NULL,
  first_seen DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_host (host)
);
