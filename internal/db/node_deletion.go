package db

// ─── Node Deletion ──────────────────────────────────────────────────────────

// SetNodeDeletionPhase transitions a node through the graceful deletion flow.
func (d *DB) SetNodeDeletionPhase(nodeID uint64, phase string) error {
	_, err := d.db.Exec("UPDATE nodes SET deletion_phase = ? WHERE id = ?", phase, nodeID)
	return err
}

// StoreNodeSecretsExport saves the AES-encrypted secrets blob reported by the CLI.
func (d *DB) StoreNodeSecretsExport(nodeID uint64, encryptedSecrets string) error {
	_, err := d.db.Exec("UPDATE nodes SET secrets_export_enc = ? WHERE id = ?", encryptedSecrets, nodeID)
	return err
}

// SetNodeDeletionRetainData sets whether the CLI should keep backup data on disk.
func (d *DB) SetNodeDeletionRetainData(nodeID uint64, retain bool) error {
	_, err := d.db.Exec("UPDATE nodes SET deletion_retain_data = ? WHERE id = ?", retain, nodeID)
	return err
}

// GetNodeSecretsExport returns the encrypted secrets blob for a node.
func (d *DB) GetNodeSecretsExport(nodeID uint64) (string, error) {
	var enc string
	err := d.db.QueryRow("SELECT secrets_export_enc FROM nodes WHERE id = ?", nodeID).Scan(&enc)
	return enc, err
}

// ClearNodeSecretsExport removes the stored secrets blob.
func (d *DB) ClearNodeSecretsExport(nodeID uint64) error {
	_, err := d.db.Exec("UPDATE nodes SET secrets_export_enc = '' WHERE id = ?", nodeID)
	return err
}
