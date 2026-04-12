ALTER TABLE users
  ADD COLUMN totp_secret  VARCHAR(64)  NOT NULL DEFAULT '' AFTER password_hash,
  ADD COLUMN totp_enabled TINYINT(1)   NOT NULL DEFAULT 0  AFTER totp_secret;
