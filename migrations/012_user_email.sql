ALTER TABLE users
  ADD COLUMN email VARCHAR(255) NULL AFTER username,
  ADD UNIQUE KEY uk_email (email);
