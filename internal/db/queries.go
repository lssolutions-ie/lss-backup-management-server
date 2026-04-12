package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// ─── Users ───────────────────────────────────────────────────────────────────

func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (d *DB) CreateUser(username, passwordHash, role string) (uint64, error) {
	res, err := d.db.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, passwordHash, role,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) CreateUserWithEmail(username, email, passwordHash, role string) (uint64, error) {
	var emailVal *string
	if email != "" {
		emailVal = &email
	}
	res, err := d.db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		username, emailVal, passwordHash, role,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

// GetUserByLogin finds a user by username or email (for login).
func (d *DB) GetUserByLogin(login string) (*models.User, error) {
	u := &models.User{}
	err := d.db.QueryRow(
		"SELECT id, username, email, password_hash, totp_secret, totp_enabled, force_setup, role, created_at, updated_at FROM users WHERE username = ? OR email = ?",
		login, login,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled, &u.ForceSetup, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	u := &models.User{}
	err := d.db.QueryRow(
		"SELECT id, username, email, password_hash, totp_secret, totp_enabled, force_setup, role, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled, &u.ForceSetup, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserByID(id uint64) (*models.User, error) {
	u := &models.User{}
	err := d.db.QueryRow(
		"SELECT id, username, email, password_hash, totp_secret, totp_enabled, force_setup, role, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled, &u.ForceSetup, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) ListUsers() ([]*models.User, error) {
	rows, err := d.db.Query(
		"SELECT id, username, email, password_hash, totp_secret, totp_enabled, force_setup, role, created_at, updated_at FROM users ORDER BY username",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled, &u.ForceSetup, &u.Role, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (d *DB) SetTOTPSecret(userID uint64, secret string) error {
	_, err := d.db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", secret, userID)
	return err
}

func (d *DB) EnableTOTP(userID uint64) error {
	_, err := d.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", userID)
	return err
}

func (d *DB) ClearForceSetup(userID uint64) error {
	_, err := d.db.Exec("UPDATE users SET force_setup = 0 WHERE id = ?", userID)
	return err
}

func (d *DB) DisableTOTP(userID uint64) error {
	_, err := d.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?", userID)
	return err
}

func (d *DB) UpdateUserEmail(id uint64, email string) error {
	var emailVal *string
	if email != "" {
		emailVal = &email
	}
	_, err := d.db.Exec("UPDATE users SET email = ? WHERE id = ?", emailVal, id)
	return err
}

func (d *DB) UpdateUserPassword(id uint64, passwordHash string) error {
	_, err := d.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, id)
	return err
}

func (d *DB) UpdateUser(id uint64, role string) error {
	_, err := d.db.Exec("UPDATE users SET role = ? WHERE id = ?", role, id)
	return err
}

func (d *DB) DeleteUser(id uint64) error {
	_, err := d.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// ─── User–ClientGroup access ─────────────────────────────────────────────────

func (d *DB) GetUserClientGroupIDs(userID uint64) ([]uint64, error) {
	rows, err := d.db.Query(
		"SELECT client_group_id FROM user_client_group_access WHERE user_id = ?", userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (d *DB) SetUserClientGroupAccess(userID uint64, groupIDs []uint64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec("DELETE FROM user_client_group_access WHERE user_id = ?", userID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if _, err := tx.Exec(
			"INSERT INTO user_client_group_access (user_id, client_group_id) VALUES (?, ?)",
			userID, gid,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ─── Sessions ────────────────────────────────────────────────────────────────

func (d *DB) CreateSession(token string, userID uint64, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, userID, expiresAt,
	)
	return err
}

func (d *DB) GetSessionByToken(token string) (*models.Session, error) {
	s := &models.Session{}
	err := d.db.QueryRow(
		"SELECT token, user_id, expires_at, last_active_at, created_at FROM sessions WHERE token = ?",
		token,
	).Scan(&s.Token, &s.UserID, &s.ExpiresAt, &s.LastActiveAt, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

func (d *DB) TouchSession(token string) error {
	_, err := d.db.Exec("UPDATE sessions SET last_active_at = NOW() WHERE token = ?", token)
	return err
}

func (d *DB) DeleteSession(token string) error {
	_, err := d.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (d *DB) DeleteExpiredSessions() error {
	_, err := d.db.Exec("DELETE FROM sessions WHERE expires_at < NOW()")
	return err
}

// ─── Client Groups ───────────────────────────────────────────────────────────

func (d *DB) ListClientGroups() ([]*models.ClientGroup, error) {
	rows, err := d.db.Query(`
		SELECT cg.id, cg.name, cg.created_at, COUNT(n.id) AS node_count
		FROM client_groups cg
		LEFT JOIN nodes n ON n.client_group_id = cg.id
		GROUP BY cg.id
		ORDER BY cg.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []*models.ClientGroup
	for rows.Next() {
		g := &models.ClientGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt, &g.NodeCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (d *DB) ListClientGroupsForUser(userID uint64) ([]*models.ClientGroup, error) {
	rows, err := d.db.Query(`
		SELECT cg.id, cg.name, cg.created_at, COUNT(n.id) AS node_count
		FROM client_groups cg
		INNER JOIN user_client_group_access uga ON uga.client_group_id = cg.id AND uga.user_id = ?
		LEFT JOIN nodes n ON n.client_group_id = cg.id
		GROUP BY cg.id
		ORDER BY cg.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []*models.ClientGroup
	for rows.Next() {
		g := &models.ClientGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt, &g.NodeCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (d *DB) GetClientGroupByID(id uint64) (*models.ClientGroup, error) {
	g := &models.ClientGroup{}
	err := d.db.QueryRow(
		"SELECT id, name, created_at FROM client_groups WHERE id = ?", id,
	).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (d *DB) CreateClientGroup(name string) (uint64, error) {
	res, err := d.db.Exec("INSERT INTO client_groups (name) VALUES (?)", name)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateClientGroup(id uint64, name string) error {
	_, err := d.db.Exec("UPDATE client_groups SET name = ? WHERE id = ?", name, id)
	return err
}

func (d *DB) DeleteClientGroup(id uint64) error {
	_, err := d.db.Exec("DELETE FROM client_groups WHERE id = ?", id)
	return err
}

func (d *DB) CountNodesInGroup(groupID uint64) (int, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM nodes WHERE client_group_id = ?", groupID).Scan(&n)
	return n, err
}

// ─── Nodes ───────────────────────────────────────────────────────────────────

func (d *DB) GetNodeByUID(uid string) (*models.Node, error) {
	n := &models.Node{}
	var tPort sql.NullInt32
	var tKey sql.NullString
	err := d.db.QueryRow(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at,
		       n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
		       n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
		       n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
		       n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.uid = ?`, uid).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt,
			&tPort, &n.TunnelConnected, &tKey,
			&n.HwOS, &n.HwArch, &n.HwCPUs, &n.HwHostname,
			&n.HwRAMBytes, &n.HwLANIP, &n.HwPublicIP, &n.HwStorageJSON,
			&n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	applyTunnelScan(n, tPort, tKey)
	return n, err
}

func (d *DB) GetNodeByID(id uint64) (*models.Node, error) {
	n := &models.Node{}
	var tPort sql.NullInt32
	var tKey sql.NullString
	err := d.db.QueryRow(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at,
		       n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
		       n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
		       n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
		       n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.id = ?`, id).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt,
			&tPort, &n.TunnelConnected, &tKey,
			&n.HwOS, &n.HwArch, &n.HwCPUs, &n.HwHostname,
			&n.HwRAMBytes, &n.HwLANIP, &n.HwPublicIP, &n.HwStorageJSON,
			&n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	applyTunnelScan(n, tPort, tKey)
	return n, err
}

// applyTunnelScan converts nullable scan results into the Node struct.
func applyTunnelScan(n *models.Node, port sql.NullInt32, key sql.NullString) {
	if port.Valid {
		p := int(port.Int32)
		n.TunnelPort = &p
	}
	if key.Valid {
		n.TunnelPublicKey = key.String
	}
}

func (d *DB) CreateNode(uid, name string, groupID uint64, pskEncrypted string) (uint64, error) {
	res, err := d.db.Exec(
		"INSERT INTO nodes (uid, name, client_group_id, psk_encrypted) VALUES (?, ?, ?, ?)",
		uid, name, groupID, pskEncrypted,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateNode(id uint64, name string, groupID uint64) error {
	_, err := d.db.Exec(
		"UPDATE nodes SET name = ?, client_group_id = ? WHERE id = ?",
		name, groupID, id,
	)
	return err
}

func (d *DB) UpdateNodePSK(id uint64, pskEncrypted string) error {
	_, err := d.db.Exec("UPDATE nodes SET psk_encrypted = ? WHERE id = ?", pskEncrypted, id)
	return err
}

func (d *DB) UpdateNodeSeen(id uint64, now time.Time, firstSeen bool) error {
	if firstSeen {
		_, err := d.db.Exec(
			"UPDATE nodes SET first_seen_at = ?, last_seen_at = ? WHERE id = ?",
			now, now, id,
		)
		return err
	}
	_, err := d.db.Exec("UPDATE nodes SET last_seen_at = ? WHERE id = ?", now, id)
	return err
}

func (d *DB) DeleteNode(id uint64) error {
	_, err := d.db.Exec("DELETE FROM nodes WHERE id = ?", id)
	return err
}

// UpdateNodeTunnel stores the latest reverse-tunnel info reported by a node.
// Returns true if the stored public key changed (so the caller can trigger
// regeneration of the authorized_keys file).
func (d *DB) UpdateNodeTunnel(nodeID uint64, port int, publicKey string, connected bool) (keyChanged bool, err error) {
	// Read the current stored key first.
	var cur sql.NullString
	err = d.db.QueryRow("SELECT tunnel_public_key FROM nodes WHERE id = ?", nodeID).Scan(&cur)
	if err != nil {
		return false, err
	}
	currentKey := ""
	if cur.Valid {
		currentKey = cur.String
	}

	_, err = d.db.Exec(
		`UPDATE nodes
		   SET tunnel_port = ?, tunnel_connected = ?, tunnel_public_key = ?
		 WHERE id = ?`,
		port, connected, publicKey, nodeID,
	)
	if err != nil {
		return false, err
	}
	return publicKey != currentKey, nil
}

// SetTunnelConnected updates only the tunnel_connected flag for a node.
func (d *DB) SetTunnelConnected(nodeID uint64, connected bool) error {
	_, err := d.db.Exec("UPDATE nodes SET tunnel_connected = ? WHERE id = ?", connected, nodeID)
	return err
}

// UpdateNodeHardware stores hardware info reported by a node on heartbeat.
func (d *DB) UpdateNodeHardware(nodeID uint64, hw *models.HardwareInfo) error {
	storageJSON := "[]"
	if len(hw.Storage) > 0 {
		b, _ := json.Marshal(hw.Storage)
		storageJSON = string(b)
	}
	_, err := d.db.Exec(
		`UPDATE nodes
		   SET hw_os = ?, hw_arch = ?, hw_cpus = ?, hw_hostname = ?,
		       hw_ram_bytes = ?, hw_lan_ip = ?, hw_public_ip = ?, hw_storage_json = ?
		 WHERE id = ?`,
		hw.OS, hw.Arch, hw.CPUs, hw.Hostname,
		hw.RAMBytes, hw.LANIP, hw.PublicIP, storageJSON,
		nodeID,
	)
	return err
}

// ListTunnelPublicKeys returns all non-empty tunnel public keys stored in the
// nodes table. Used to regenerate the authorized_keys file.
func (d *DB) ListTunnelPublicKeys() ([]string, error) {
	rows, err := d.db.Query(
		"SELECT tunnel_public_key FROM nodes WHERE tunnel_public_key IS NOT NULL AND tunnel_public_key != '' ORDER BY id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// WriteTunnelAuthorizedKeys atomically writes every registered tunnel public
// key to path, one per line. The file is mode 0644 and owned by whichever
// user the process runs as — on the production server that's lss-management,
// which matches the AuthorizedKeysCommand script's expected readable source.
func (d *DB) WriteTunnelAuthorizedKeys(path string) error {
	keys, err := d.ListTunnelPublicKeys()
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tunnel_authkeys_*")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck
	if err := f.Chmod(0o644); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	for _, k := range keys {
		key := strings.TrimRight(k, "\n")
		// Enforce restrict,port-forwarding prefix server-side regardless of
		// what the client sends. Strip any existing prefix to avoid duplication.
		key = strings.TrimPrefix(key, "restrict,port-forwarding ")
		line := "restrict,port-forwarding " + key + "\n"
		if _, err := f.WriteString(line); err != nil {
			f.Close() //nolint:errcheck
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// ListNodesWithStatus returns all nodes visible to the user, enriched with job
// count and worst job status. groupIDs is nil for superadmins (all nodes).
// Runs as a single JOIN + GROUP BY query (no N+1).
func (d *DB) ListNodesWithStatus(groupIDs []uint64) ([]*models.NodeWithStatus, error) {
	query := `
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at,
		       n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
		       n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
		       n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
		       n.created_at,
		       COUNT(js.id) AS job_count,
		       CASE
		         WHEN SUM(js.last_status = 'failure') > 0 THEN 'failure'
		         WHEN SUM(js.last_status = '')        > 0 THEN 'never_run'
		         WHEN SUM(js.last_status = 'success') > 0 THEN 'success'
		         ELSE ''
		       END AS worst_status
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		LEFT JOIN job_snapshots js ON js.node_id = n.id`
	args := []interface{}{}
	if len(groupIDs) > 0 {
		query += " WHERE n.client_group_id IN (" + placeholders(len(groupIDs)) + ")"
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += ` GROUP BY n.id, n.uid, n.name, n.client_group_id, cg.name,
	                    n.psk_encrypted, n.first_seen_at, n.last_seen_at,
	                    n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
	                    n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
	                    n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
	                    n.created_at
	          ORDER BY n.name`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeWithStatus
	for rows.Next() {
		ns := &models.NodeWithStatus{}
		var tPort sql.NullInt32
		var tKey sql.NullString
		if err := rows.Scan(
			&ns.ID, &ns.UID, &ns.Name, &ns.ClientGroupID, &ns.ClientGroup,
			&ns.PSKEncrypted, &ns.FirstSeenAt, &ns.LastSeenAt,
			&tPort, &ns.TunnelConnected, &tKey,
			&ns.HwOS, &ns.HwArch, &ns.HwCPUs, &ns.HwHostname,
			&ns.HwRAMBytes, &ns.HwLANIP, &ns.HwPublicIP, &ns.HwStorageJSON,
			&ns.CreatedAt,
			&ns.JobCount, &ns.WorstStatus,
		); err != nil {
			return nil, err
		}
		applyTunnelScan(&ns.Node, tPort, tKey)
		nodes = append(nodes, ns)
	}
	return nodes, rows.Err()
}

// ListOfflineNodes returns nodes that last checked in more than 15 minutes ago
// and have checked in at least once (first_seen_at IS NOT NULL).
func (d *DB) ListOfflineNodes() ([]*models.Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at,
		       n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
		       n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
		       n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
		       n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.first_seen_at IS NOT NULL
		  AND (n.last_seen_at IS NULL OR n.last_seen_at < DATE_SUB(NOW(), INTERVAL 15 MINUTE))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []*models.Node
	for rows.Next() {
		n := &models.Node{}
		var tPort sql.NullInt32
		var tKey sql.NullString
		if err := rows.Scan(
			&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt,
			&tPort, &n.TunnelConnected, &tKey,
			&n.HwOS, &n.HwArch, &n.HwCPUs, &n.HwHostname,
			&n.HwRAMBytes, &n.HwLANIP, &n.HwPublicIP, &n.HwStorageJSON,
			&n.CreatedAt,
		); err != nil {
			return nil, err
		}
		applyTunnelScan(n, tPort, tKey)
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// ─── Tags ───────────────────────────────────────────────────────────────────

func (d *DB) CreateTag(name, color string) (uint64, error) {
	return d.CreateTagWithTextColor(name, color, "#ffffff")
}

func (d *DB) CreateTagWithTextColor(name, color, textColor string) (uint64, error) {
	res, err := d.db.Exec("INSERT INTO tags (name, color, text_color) VALUES (?, ?, ?)", name, color, textColor)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) ListTags() ([]*models.Tag, error) {
	rows, err := d.db.Query("SELECT id, name, color, text_color FROM tags ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []*models.Tag
	for rows.Next() {
		t := &models.Tag{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (d *DB) DeleteTag(id uint64) error {
	_, err := d.db.Exec("DELETE FROM tags WHERE id = ?", id)
	return err
}

func (d *DB) GetNodeTags(nodeID uint64) ([]models.Tag, error) {
	rows, err := d.db.Query(
		"SELECT t.id, t.name, t.color, t.text_color FROM tags t JOIN node_tags nt ON nt.tag_id = t.id WHERE nt.node_id = ? ORDER BY t.name",
		nodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []models.Tag
	for rows.Next() {
		var t models.Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (d *DB) SetNodeTags(nodeID uint64, tagIDs []uint64) error {
	_, err := d.db.Exec("DELETE FROM node_tags WHERE node_id = ?", nodeID)
	if err != nil {
		return err
	}
	for _, tid := range tagIDs {
		if _, err := d.db.Exec("INSERT INTO node_tags (node_id, tag_id) VALUES (?, ?)", nodeID, tid); err != nil {
			return err
		}
	}
	return nil
}

// GetAllNodeTags returns tags for all nodes in a single query, keyed by node ID.
func (d *DB) GetAllNodeTags() (map[uint64][]models.Tag, error) {
	rows, err := d.db.Query(
		"SELECT nt.node_id, t.id, t.name, t.color, t.text_color FROM node_tags nt JOIN tags t ON t.id = nt.tag_id ORDER BY t.name",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[uint64][]models.Tag)
	for rows.Next() {
		var nodeID uint64
		var t models.Tag
		if err := rows.Scan(&nodeID, &t.ID, &t.Name, &t.Color, &t.TextColor); err != nil {
			return nil, err
		}
		m[nodeID] = append(m[nodeID], t)
	}
	return m, rows.Err()
}

func (d *DB) UpdateTag(id uint64, name, color, textColor string) error {
	_, err := d.db.Exec("UPDATE tags SET name = ?, color = ?, text_color = ? WHERE id = ?", name, color, textColor, id)
	return err
}

func (d *DB) GetTagByID(id uint64) (*models.Tag, error) {
	t := &models.Tag{}
	err := d.db.QueryRow("SELECT id, name, color, text_color FROM tags WHERE id = ?", id).Scan(&t.ID, &t.Name, &t.Color, &t.TextColor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// GetUserTagIDs returns the tag IDs a user has access to.
func (d *DB) GetUserTagIDs(userID uint64) ([]uint64, error) {
	rows, err := d.db.Query("SELECT tag_id FROM user_tags WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetUserTags sets the tags a user has access to.
func (d *DB) SetUserTags(userID uint64, tagIDs []uint64) error {
	_, err := d.db.Exec("DELETE FROM user_tags WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	for _, tid := range tagIDs {
		if _, err := d.db.Exec("INSERT INTO user_tags (user_id, tag_id) VALUES (?, ?)", userID, tid); err != nil {
			return err
		}
	}
	return nil
}

// GetTagUsers returns user IDs that have access to a tag.
func (d *DB) GetTagUserIDs(tagID uint64) ([]uint64, error) {
	rows, err := d.db.Query("SELECT user_id FROM user_tags WHERE tag_id = ?", tagID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetTagUsers sets which users have access to a tag.
func (d *DB) SetTagUsers(tagID uint64, userIDs []uint64) error {
	_, err := d.db.Exec("DELETE FROM user_tags WHERE tag_id = ?", tagID)
	if err != nil {
		return err
	}
	for _, uid := range userIDs {
		if _, err := d.db.Exec("INSERT INTO user_tags (user_id, tag_id) VALUES (?, ?)", uid, tagID); err != nil {
			return err
		}
	}
	return nil
}

// ─── SMTP Config ────────────────────────────────────────────────────────────

func (d *DB) GetSMTPConfig() (*models.SMTPConfig, error) {
	c := &models.SMTPConfig{}
	err := d.db.QueryRow(
		"SELECT host, port, username, password_enc, from_address, from_name, use_tls, enabled FROM smtp_config WHERE id = 1",
	).Scan(&c.Host, &c.Port, &c.Username, &c.PasswordEnc, &c.FromAddress, &c.FromName, &c.UseTLS, &c.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &models.SMTPConfig{Port: 587, FromName: "LSS Backup", UseTLS: true}, nil
	}
	return c, err
}

func (d *DB) SaveSMTPConfig(c *models.SMTPConfig) error {
	_, err := d.db.Exec(
		`UPDATE smtp_config
		 SET host = ?, port = ?, username = ?, password_enc = ?,
		     from_address = ?, from_name = ?, use_tls = ?, enabled = ?
		 WHERE id = 1`,
		c.Host, c.Port, c.Username, c.PasswordEnc,
		c.FromAddress, c.FromName, c.UseTLS, c.Enabled,
	)
	return err
}

// ─── SSH Host Keys (TOFU) ───────────────────────────────────────────────────

// GetSSHHostKey returns the stored host key for the given host, or empty string if none.
func (d *DB) GetSSHHostKey(host string) (keyType, keyData string, err error) {
	err = d.db.QueryRow(
		"SELECT key_type, key_data FROM ssh_host_keys WHERE host = ?", host,
	).Scan(&keyType, &keyData)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return keyType, keyData, err
}

// SaveSSHHostKey stores a host key (TOFU: trust on first use).
func (d *DB) SaveSSHHostKey(host, keyType, keyData string) error {
	_, err := d.db.Exec(
		`INSERT INTO ssh_host_keys (host, key_type, key_data) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE key_type = VALUES(key_type), key_data = VALUES(key_data)`,
		host, keyType, keyData,
	)
	return err
}

// ─── Job snapshots ───────────────────────────────────────────────────────────

func (d *DB) ListJobSnapshots(nodeID uint64) ([]models.JobSnapshot, error) {
	rows, err := d.db.Query(`
		SELECT id, node_id, job_id, job_name, program, enabled,
		       last_status, last_run_at, last_run_duration_seconds,
		       last_error, next_run_at, schedule_description, config_json, updated_at
		FROM job_snapshots WHERE node_id = ? ORDER BY job_id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []models.JobSnapshot
	for rows.Next() {
		j := models.JobSnapshot{}
		var config sql.NullString
		if err := rows.Scan(
			&j.ID, &j.NodeID, &j.JobID, &j.JobName, &j.Program, &j.Enabled,
			&j.LastStatus, &j.LastRunAt, &j.LastRunDurationSeconds,
			&j.LastError, &j.NextRunAt, &j.ScheduleDescription, &config, &j.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if config.Valid {
			j.ConfigJSON = config.String
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// DeleteStaleJobSnapshots removes job snapshots for a node that are no longer
// reported by the CLI. Returns the number of rows deleted.
func (d *DB) DeleteStaleJobSnapshots(nodeID uint64, currentJobIDs []string) (int64, error) {
	if len(currentJobIDs) == 0 {
		// Node reports zero jobs — delete all.
		res, err := d.db.Exec("DELETE FROM job_snapshots WHERE node_id = ?", nodeID)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}

	query := "DELETE FROM job_snapshots WHERE node_id = ? AND job_id NOT IN (" + placeholders(len(currentJobIDs)) + ")"
	args := []interface{}{nodeID}
	for _, id := range currentJobIDs {
		args = append(args, id)
	}
	res, err := d.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) UpsertJobSnapshot(nodeID uint64, job models.JobStatus) error {
	// job.Config is populated only on heartbeat reports. On post_run reports
	// it's nil/empty — pass NULL so ON DUPLICATE KEY UPDATE's COALESCE
	// preserves whatever config the last heartbeat stored.
	var configArg interface{}
	if len(job.Config) > 0 && string(job.Config) != "null" {
		configArg = string(job.Config)
	}

	_, err := d.db.Exec(`
		INSERT INTO job_snapshots
		  (node_id, job_id, job_name, program, enabled, last_status,
		   last_run_at, last_run_duration_seconds, last_error, next_run_at,
		   schedule_description, config_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		  job_name                  = VALUES(job_name),
		  program                   = VALUES(program),
		  enabled                   = VALUES(enabled),
		  last_status               = VALUES(last_status),
		  last_run_at               = VALUES(last_run_at),
		  last_run_duration_seconds = VALUES(last_run_duration_seconds),
		  last_error                = VALUES(last_error),
		  next_run_at               = VALUES(next_run_at),
		  schedule_description      = VALUES(schedule_description),
		  config_json               = COALESCE(VALUES(config_json), config_json),
		  updated_at                = CURRENT_TIMESTAMP`,
		nodeID, job.ID, job.Name, job.Program, job.Enabled, job.LastStatus,
		job.LastRunAt, job.LastRunDurationSeconds, job.LastError, job.NextRunAt,
		job.ScheduleDescription, configArg,
	)
	return err
}

// ─── Node reports ────────────────────────────────────────────────────────────

func (d *DB) InsertNodeReport(nodeID uint64, reportedAt time.Time, reportType, payloadJSON string) error {
	_, err := d.db.Exec(
		"INSERT INTO node_reports (node_id, reported_at, report_type, payload_json) VALUES (?, ?, ?, ?)",
		nodeID, reportedAt, reportType, payloadJSON,
	)
	return err
}

func (d *DB) ListNodeReports(nodeID uint64, limit, offset int) ([]*models.NodeReport, error) {
	rows, err := d.db.Query(`
		SELECT id, node_id, reported_at, received_at, report_type, payload_json
		FROM node_reports
		WHERE node_id = ?
		ORDER BY reported_at DESC
		LIMIT ? OFFSET ?`, nodeID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []*models.NodeReport
	for rows.Next() {
		r := &models.NodeReport{}
		if err := rows.Scan(&r.ID, &r.NodeID, &r.ReportedAt, &r.ReceivedAt, &r.ReportType, &r.PayloadJSON); err != nil {
			return nil, err
		}
		// compute job count and worst status from stored JSON
		r.JobCount, r.WorstStatus = reportStats(r.PayloadJSON)
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

func (d *DB) CountNodeReports(nodeID uint64) (int, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM node_reports WHERE node_id = ?", nodeID).Scan(&n)
	return n, err
}

func (d *DB) reportFilterWhere(f models.ReportFilter) (string, []interface{}) {
	where := "WHERE node_id = ?"
	args := []interface{}{f.NodeID}
	if f.Type != "" {
		where += " AND report_type = ?"
		args = append(args, f.Type)
	}
	if f.From != "" {
		where += " AND reported_at >= ?"
		args = append(args, f.From+" 00:00:00")
	}
	if f.To != "" {
		where += " AND reported_at <= ?"
		args = append(args, f.To+" 23:59:59")
	}
	return where, args
}

func (d *DB) CountNodeReportsFiltered(f models.ReportFilter) (int, error) {
	where, args := d.reportFilterWhere(f)
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM node_reports "+where, args...).Scan(&n)
	return n, err
}

func (d *DB) ListNodeReportsFiltered(f models.ReportFilter) ([]*models.NodeReport, error) {
	where, args := d.reportFilterWhere(f)
	args = append(args, f.Limit, f.Offset)
	rows, err := d.db.Query(
		"SELECT id, node_id, reported_at, received_at, report_type, payload_json FROM node_reports "+
			where+" ORDER BY reported_at DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []*models.NodeReport
	for rows.Next() {
		r := &models.NodeReport{}
		if err := rows.Scan(&r.ID, &r.NodeID, &r.ReportedAt, &r.ReceivedAt, &r.ReportType, &r.PayloadJSON); err != nil {
			return nil, err
		}
		r.JobCount, r.WorstStatus = reportStats(r.PayloadJSON)
		// Filter by status client-side computed field.
		if f.Status != "" && r.WorstStatus != f.Status {
			continue
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

// ─── Dashboard stats ─────────────────────────────────────────────────────────

// GetDashboardStats returns the four summary counters for the dashboard cards.
// Runs as two queries: one for per-node counters, one for failing-node count.
func (d *DB) GetDashboardStats(groupIDs []uint64) (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}
	where, args := groupFilter("n.client_group_id", groupIDs)

	// One query covers total / online / never-seen.
	q1 := `
		SELECT
		  COUNT(*) AS total,
		  SUM(n.last_seen_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)) AS online,
		  SUM(n.first_seen_at IS NULL) AS never_seen
		FROM nodes n` + where
	var online, never sql.NullInt64
	if err := d.db.QueryRow(q1, args...).Scan(&stats.TotalNodes, &online, &never); err != nil {
		return nil, fmt.Errorf("dashboard node counters: %w", err)
	}
	stats.OnlineNodes = int(online.Int64)
	stats.NeverSeenNodes = int(never.Int64)

	// Failing nodes: distinct nodes with at least one failing job snapshot.
	q2 := `
		SELECT COUNT(DISTINCT js.node_id)
		FROM job_snapshots js
		JOIN nodes n ON n.id = js.node_id
		WHERE js.last_status = 'failure'`
	if where != "" {
		// where already starts with " WHERE ..." — convert to extra AND.
		q2 += " AND " + where[len(" WHERE "):]
	}
	if err := d.db.QueryRow(q2, args...).Scan(&stats.FailingNodes); err != nil {
		return nil, fmt.Errorf("dashboard failing counter: %w", err)
	}

	return stats, nil
}

// ListGroupsWithStats returns each client group with node count and worst job
// status. groupIDs is nil for superadmins (all groups). Single JOIN query, no
// per-group subqueries.
func (d *DB) ListGroupsWithStats(groupIDs []uint64) ([]*models.GroupWithStats, error) {
	query := `
		SELECT cg.id, cg.name, cg.created_at,
		       COUNT(DISTINCT n.id) AS node_count,
		       CASE
		         WHEN SUM(js.last_status = 'failure') > 0 THEN 'failure'
		         WHEN SUM(js.last_status = '')        > 0 THEN 'never_run'
		         WHEN SUM(js.last_status = 'success') > 0 THEN 'success'
		         ELSE ''
		       END AS worst_status
		FROM client_groups cg
		LEFT JOIN nodes n          ON n.client_group_id = cg.id
		LEFT JOIN job_snapshots js ON js.node_id = n.id`
	args := []interface{}{}
	if len(groupIDs) > 0 {
		query += " WHERE cg.id IN (" + placeholders(len(groupIDs)) + ")"
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += " GROUP BY cg.id, cg.name, cg.created_at ORDER BY cg.name"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.GroupWithStats
	for rows.Next() {
		gws := &models.GroupWithStats{}
		if err := rows.Scan(
			&gws.ID, &gws.Name, &gws.CreatedAt, &gws.NodeCount, &gws.WorstStatus,
		); err != nil {
			return nil, err
		}
		result = append(result, gws)
	}
	return result, rows.Err()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func placeholders(n int) string {
	if n == 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}

func groupFilter(col string, groupIDs []uint64) (string, []interface{}) {
	if len(groupIDs) == 0 {
		return "", nil
	}
	args := make([]interface{}, len(groupIDs))
	for i, id := range groupIDs {
		args[i] = id
	}
	return " WHERE " + col + " IN (" + placeholders(len(groupIDs)) + ")", args
}

// reportStats extracts job count and worst status from a stored payload JSON.
func reportStats(payloadJSON string) (int, string) {
	var payload struct {
		Jobs []struct {
			LastStatus string `json:"last_status"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return 0, ""
	}
	worst := ""
	for _, j := range payload.Jobs {
		switch j.LastStatus {
		case "failure":
			worst = "failure"
		case "success":
			if worst != "failure" {
				worst = "success"
			}
		default:
			if worst == "" {
				worst = "never_run"
			}
		}
	}
	return len(payload.Jobs), worst
}
