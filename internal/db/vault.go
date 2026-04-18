package db

import (
	"database/sql"

	"github.com/lssolutions-ie/lss-backup-server/internal/crypto"
)

// VaultEntry represents a single encrypted credential for a node.
type VaultEntry struct {
	ID        uint64
	NodeID    uint64
	EntryType string // psk, ssh_username, ssh_password, cli_encrypt_password
	ValueEnc  string
}

// GetVaultSentinel returns the stored sentinel, or "" if vault is not set up.
func (d *DB) GetVaultSentinel() (string, error) {
	var s sql.NullString
	err := d.db.QueryRow("SELECT vault_sentinel_enc FROM server_tuning WHERE id = 1").Scan(&s)
	if err != nil {
		return "", err
	}
	if !s.Valid {
		return "", nil
	}
	return s.String, nil
}

// SetVaultSentinel stores the encrypted sentinel for vault password verification.
func (d *DB) SetVaultSentinel(sentinelEnc string) error {
	_, err := d.db.Exec("UPDATE server_tuning SET vault_sentinel_enc = ? WHERE id = 1", sentinelEnc)
	return err
}

// UpsertVaultEntry inserts or updates a vault entry for a node.
func (d *DB) UpsertVaultEntry(nodeID uint64, entryType, valueEnc string) error {
	_, err := d.db.Exec(`
		INSERT INTO vault_entries (node_id, entry_type, value_enc)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE value_enc = VALUES(value_enc), updated_at = NOW()`,
		nodeID, entryType, valueEnc)
	return err
}

// GetVaultEntries returns all vault entries for a node.
func (d *DB) GetVaultEntries(nodeID uint64) ([]VaultEntry, error) {
	rows, err := d.db.Query("SELECT id, node_id, entry_type, value_enc FROM vault_entries WHERE node_id = ? ORDER BY entry_type", nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []VaultEntry
	for rows.Next() {
		var e VaultEntry
		if err := rows.Scan(&e.ID, &e.NodeID, &e.EntryType, &e.ValueEnc); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// DeleteVaultEntry removes a specific vault entry.
func (d *DB) DeleteVaultEntry(id uint64) error {
	_, err := d.db.Exec("DELETE FROM vault_entries WHERE id = ?", id)
	return err
}

// DeleteVaultEntriesForNode removes all vault entries for a node.
func (d *DB) DeleteVaultEntriesForNode(nodeID uint64) error {
	_, err := d.db.Exec("DELETE FROM vault_entries WHERE node_id = ?", nodeID)
	return err
}

// VaultIsSetUp returns true if a vault sentinel exists.
func (d *DB) VaultIsSetUp() (bool, error) {
	s, err := d.GetVaultSentinel()
	if err != nil {
		return false, err
	}
	return s != "", nil
}

// AutoStoreNodePSK stores the node's PSK in the vault (called during node registration).
func (d *DB) AutoStoreNodePSK(nodeID uint64, psk string, appKey []byte) error {
	enc, err := crypto.VaultEncrypt(psk, appKey)
	if err != nil {
		return err
	}
	return d.UpsertVaultEntry(nodeID, "psk", enc)
}
