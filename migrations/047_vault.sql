-- Password Vault: double-encrypted credential storage per node
CREATE TABLE vault_entries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id BIGINT UNSIGNED NOT NULL,
  entry_type VARCHAR(32) NOT NULL,
  value_enc TEXT NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_node_type (node_id, entry_type),
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

-- Sentinel for vault password verification (encrypted known plaintext)
ALTER TABLE server_tuning ADD COLUMN vault_sentinel_enc TEXT;
