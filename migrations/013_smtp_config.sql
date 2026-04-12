CREATE TABLE IF NOT EXISTS smtp_config (
  id            INT UNSIGNED NOT NULL DEFAULT 1 PRIMARY KEY,
  host          VARCHAR(255) NOT NULL DEFAULT '',
  port          INT          NOT NULL DEFAULT 587,
  username      VARCHAR(255) NOT NULL DEFAULT '',
  password_enc  TEXT         NOT NULL,
  from_address  VARCHAR(255) NOT NULL DEFAULT '',
  from_name     VARCHAR(255) NOT NULL DEFAULT 'LSS Backup',
  use_tls       TINYINT(1)   NOT NULL DEFAULT 1,
  enabled       TINYINT(1)   NOT NULL DEFAULT 0,
  updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT chk_single_row CHECK (id = 1)
);

INSERT IGNORE INTO smtp_config (id, password_enc) VALUES (1, '');
