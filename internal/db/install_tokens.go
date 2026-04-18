package db

import (
	"database/sql"
	"time"
)

// InstallToken represents a one-time install token for server-assisted node deployment.
type InstallToken struct {
	ID        uint64
	TokenHash string
	NodeID    uint64
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedBy *uint64
	CreatedAt time.Time
}

// CreateInstallToken inserts a new hashed token linked to a pending node.
func (d *DB) CreateInstallToken(tokenHash string, nodeID uint64, expiresAt time.Time, createdBy uint64) error {
	_, err := d.db.Exec(
		`INSERT INTO node_install_tokens (token_hash, node_id, expires_at, created_by)
		 VALUES (?, ?, ?, ?)`,
		tokenHash, nodeID, expiresAt, createdBy,
	)
	return err
}

// GetInstallTokenByHash looks up a token by its SHA-256 hash.
func (d *DB) GetInstallTokenByHash(tokenHash string) (*InstallToken, error) {
	t := &InstallToken{}
	var usedAt sql.NullTime
	var createdBy sql.NullInt64

	err := d.db.QueryRow(
		`SELECT id, token_hash, node_id, expires_at, used_at, created_by, created_at
		 FROM node_install_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&t.ID, &t.TokenHash, &t.NodeID, &t.ExpiresAt, &usedAt, &createdBy, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if usedAt.Valid {
		t.UsedAt = &usedAt.Time
	}
	if createdBy.Valid {
		v := uint64(createdBy.Int64)
		t.CreatedBy = &v
	}
	return t, nil
}

// MarkInstallTokenUsed sets used_at = NOW() on the given token.
func (d *DB) MarkInstallTokenUsed(id uint64) error {
	_, err := d.db.Exec(
		`UPDATE node_install_tokens SET used_at = NOW() WHERE id = ?`,
		id,
	)
	return err
}

// ListInstallTokens returns the most recent tokens up to limit.
func (d *DB) ListInstallTokens(limit int) ([]*InstallToken, error) {
	rows, err := d.db.Query(
		`SELECT id, token_hash, node_id, expires_at, used_at, created_by, created_at
		 FROM node_install_tokens ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*InstallToken
	for rows.Next() {
		t := &InstallToken{}
		var usedAt sql.NullTime
		var createdBy sql.NullInt64
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.NodeID, &t.ExpiresAt, &usedAt, &createdBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		if usedAt.Valid {
			t.UsedAt = &usedAt.Time
		}
		if createdBy.Valid {
			v := uint64(createdBy.Int64)
			t.CreatedBy = &v
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// PruneExpiredPendingNodes deletes nodes that were created via server-assisted
// install but never completed registration (no heartbeat received), AND whose
// install tokens have all expired. Runs hourly from the retention worker.
func (d *DB) PruneExpiredPendingNodes() (int64, error) {
	res, err := d.db.Exec(`
		DELETE n FROM nodes n
		WHERE n.first_seen_at IS NULL
		  AND NOT EXISTS (
		    SELECT 1 FROM node_install_tokens t
		    WHERE t.node_id = n.id
		      AND (t.used_at IS NULL AND t.expires_at > NOW())
		  )
		  AND EXISTS (
		    SELECT 1 FROM node_install_tokens t2
		    WHERE t2.node_id = n.id
		  )
		  AND n.created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CreatePendingNode inserts a minimal node row for server-assisted deployment.
// Name is set to the UID initially; the first heartbeat populates the real hostname.
func (d *DB) CreatePendingNode(uid string, pskEncrypted string, clientGroupID uint64) (uint64, error) {
	res, err := d.db.Exec(
		`INSERT INTO nodes (uid, name, client_group_id, psk_encrypted, hw_storage_json, dr_last_error, secrets_export_enc)
		 VALUES (?, ?, ?, ?, '[]', '', '')`,
		uid, uid, clientGroupID, pskEncrypted,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}
