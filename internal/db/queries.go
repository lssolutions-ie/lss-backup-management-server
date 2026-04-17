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
		SELECT cg.id, cg.name, cg.rank, cg.created_at, COUNT(n.id) AS node_count
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
		if err := rows.Scan(&g.ID, &g.Name, &g.Rank, &g.CreatedAt, &g.NodeCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (d *DB) ListClientGroupsForUser(userID uint64) ([]*models.ClientGroup, error) {
	rows, err := d.db.Query(`
		SELECT cg.id, cg.name, cg.rank, cg.created_at, COUNT(n.id) AS node_count
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
		if err := rows.Scan(&g.ID, &g.Name, &g.Rank, &g.CreatedAt, &g.NodeCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (d *DB) GetClientGroupByID(id uint64) (*models.ClientGroup, error) {
	g := &models.ClientGroup{}
	err := d.db.QueryRow(
		"SELECT id, name, `rank`, created_at FROM client_groups WHERE id = ?", id,
	).Scan(&g.ID, &g.Name, &g.Rank, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (d *DB) CreateClientGroup(name, rank string) (uint64, error) {
	if rank == "" {
		rank = "bronze"
	}
	res, err := d.db.Exec("INSERT INTO client_groups (name, `rank`) VALUES (?, ?)", name, rank)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateClientGroup(id uint64, name, rank string) error {
	if rank == "" {
		rank = "bronze"
	}
	_, err := d.db.Exec("UPDATE client_groups SET name = ?, `rank` = ? WHERE id = ?", name, rank, id)
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
		       n.created_at,
		       n.dr_enabled, n.dr_interval_hours, n.dr_last_backup_at,
		       n.dr_last_status, n.dr_last_error, n.dr_snapshot_count,
		       n.dr_force_run, n.dr_config_version,
		       n.cli_version, n.cli_update_pending,
		       n.deletion_phase, n.secrets_export_enc, n.deletion_retain_data
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.uid = ?`, uid).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt,
			&tPort, &n.TunnelConnected, &tKey,
			&n.HwOS, &n.HwArch, &n.HwCPUs, &n.HwHostname,
			&n.HwRAMBytes, &n.HwLANIP, &n.HwPublicIP, &n.HwStorageJSON,
			&n.CreatedAt,
			&n.DREnabled, &n.DRIntervalHours, &n.DRLastBackupAt,
			&n.DRLastStatus, &n.DRLastError, &n.DRSnapshotCount,
			&n.DRForceRun, &n.DRConfigVersion,
			&n.CLIVersion, &n.CLIUpdatePending,
			&n.DeletionPhase, &n.SecretsExportEnc, &n.DeletionRetainData)
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
		       n.created_at,
		       n.dr_enabled, n.dr_interval_hours, n.dr_last_backup_at,
		       n.dr_last_status, n.dr_last_error, n.dr_snapshot_count,
		       n.dr_force_run, n.dr_config_version,
		       n.cli_version, n.cli_update_pending,
		       n.deletion_phase, n.secrets_export_enc, n.deletion_retain_data
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.id = ?`, id).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt,
			&tPort, &n.TunnelConnected, &tKey,
			&n.HwOS, &n.HwArch, &n.HwCPUs, &n.HwHostname,
			&n.HwRAMBytes, &n.HwLANIP, &n.HwPublicIP, &n.HwStorageJSON,
			&n.CreatedAt,
			&n.DREnabled, &n.DRIntervalHours, &n.DRLastBackupAt,
			&n.DRLastStatus, &n.DRLastError, &n.DRSnapshotCount,
			&n.DRForceRun, &n.DRConfigVersion,
			&n.CLIVersion, &n.CLIUpdatePending,
			&n.DeletionPhase, &n.SecretsExportEnc, &n.DeletionRetainData)
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
		       n.cli_version, n.cli_update_pending,
		       n.dr_enabled,
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
	// Only show registered nodes (first heartbeat received). Pending nodes
	// from server-assisted install live on /settings/pending-nodes until
	// their first heartbeat completes registration.
	whereParts := []string{"n.first_seen_at IS NOT NULL"}
	if len(groupIDs) > 0 {
		whereParts = append(whereParts, "n.client_group_id IN ("+placeholders(len(groupIDs))+")")
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += " WHERE " + strings.Join(whereParts, " AND ")
	query += ` GROUP BY n.id, n.uid, n.name, n.client_group_id, cg.name,
	                    n.psk_encrypted, n.first_seen_at, n.last_seen_at,
	                    n.tunnel_port, n.tunnel_connected, n.tunnel_public_key,
	                    n.hw_os, n.hw_arch, n.hw_cpus, n.hw_hostname,
	                    n.hw_ram_bytes, n.hw_lan_ip, n.hw_public_ip, n.hw_storage_json,
	                    n.created_at, n.cli_version, n.cli_update_pending
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
			&ns.CLIVersion, &ns.CLIUpdatePending,
			&ns.DREnabled,
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

// GetNodesUsingTags returns, for each given tag ID, the list of (node id, node name) using it.
func (d *DB) GetNodesUsingTags(tagIDs []uint64) (map[uint64][]struct {
	NodeID   uint64
	NodeName string
	TagName  string
}, error) {
	result := make(map[uint64][]struct {
		NodeID   uint64
		NodeName string
		TagName  string
	})
	if len(tagIDs) == 0 {
		return result, nil
	}
	query := "SELECT nt.tag_id, n.id, n.name, t.name FROM node_tags nt JOIN nodes n ON n.id = nt.node_id JOIN tags t ON t.id = nt.tag_id WHERE nt.tag_id IN (" + placeholders(len(tagIDs)) + ") ORDER BY n.name"
	args := make([]interface{}, len(tagIDs))
	for i, id := range tagIDs {
		args[i] = id
	}
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tagID uint64
		var entry struct {
			NodeID   uint64
			NodeName string
			TagName  string
		}
		if err := rows.Scan(&tagID, &entry.NodeID, &entry.NodeName, &entry.TagName); err != nil {
			return nil, err
		}
		result[tagID] = append(result[tagID], entry)
	}
	return result, rows.Err()
}

// GetUsersUsingUserTags returns, for each given user-tag ID, the list of (user id, username) using it.
func (d *DB) GetUsersUsingUserTags(userTagIDs []uint64) (map[uint64][]struct {
	UserID   uint64
	Username string
	TagName  string
}, error) {
	result := make(map[uint64][]struct {
		UserID   uint64
		Username string
		TagName  string
	})
	if len(userTagIDs) == 0 {
		return result, nil
	}
	query := "SELECT utl.user_tag_id, u.id, u.username, utc.name FROM user_tag_links utl JOIN users u ON u.id = utl.user_id JOIN user_tag_catalog utc ON utc.id = utl.user_tag_id WHERE utl.user_tag_id IN (" + placeholders(len(userTagIDs)) + ") ORDER BY u.username"
	args := make([]interface{}, len(userTagIDs))
	for i, id := range userTagIDs {
		args[i] = id
	}
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tagID uint64
		var entry struct {
			UserID   uint64
			Username string
			TagName  string
		}
		if err := rows.Scan(&tagID, &entry.UserID, &entry.Username, &entry.TagName); err != nil {
			return nil, err
		}
		result[tagID] = append(result[tagID], entry)
	}
	return result, rows.Err()
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

// ─── User Tags (separate catalog from node tags) ────────────────────────────

func (d *DB) ListUserTags() ([]*models.UserTag, error) {
	rows, err := d.db.Query(
		"SELECT id, name, color, text_color, created_at FROM user_tag_catalog ORDER BY name",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.UserTag
	for rows.Next() {
		t := &models.UserTag{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) GetUserTagByID(id uint64) (*models.UserTag, error) {
	t := &models.UserTag{}
	err := d.db.QueryRow(
		"SELECT id, name, color, text_color, created_at FROM user_tag_catalog WHERE id = ?", id,
	).Scan(&t.ID, &t.Name, &t.Color, &t.TextColor, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (d *DB) CreateUserTag(name, color, textColor string) (uint64, error) {
	if color == "" {
		color = "#206bc4"
	}
	if textColor == "" {
		textColor = "#f0f0f0"
	}
	res, err := d.db.Exec("INSERT INTO user_tag_catalog (name, color, text_color) VALUES (?, ?, ?)", name, color, textColor)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateUserTag(id uint64, name, color, textColor string) error {
	_, err := d.db.Exec("UPDATE user_tag_catalog SET name = ?, color = ?, text_color = ? WHERE id = ?", name, color, textColor, id)
	return err
}

func (d *DB) DeleteUserTag(id uint64) error {
	_, err := d.db.Exec("DELETE FROM user_tag_catalog WHERE id = ?", id)
	return err
}

// GetUserTagsForUser returns the UserTags attached to a specific user.
func (d *DB) GetUserTagsForUser(userID uint64) ([]models.UserTag, error) {
	rows, err := d.db.Query(
		"SELECT utc.id, utc.name, utc.color, utc.text_color, utc.created_at FROM user_tag_catalog utc JOIN user_tag_links utl ON utl.user_tag_id = utc.id WHERE utl.user_id = ? ORDER BY utc.name",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []models.UserTag
	for rows.Next() {
		var t models.UserTag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor, &t.CreatedAt); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

// GetAllUserTagsByUser returns user tags for all users, keyed by user ID.
func (d *DB) GetAllUserTagsByUser() (map[uint64][]models.UserTag, error) {
	rows, err := d.db.Query(
		"SELECT utl.user_id, utc.id, utc.name, utc.color, utc.text_color, utc.created_at FROM user_tag_links utl JOIN user_tag_catalog utc ON utc.id = utl.user_tag_id ORDER BY utc.name",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[uint64][]models.UserTag)
	for rows.Next() {
		var userID uint64
		var t models.UserTag
		if err := rows.Scan(&userID, &t.ID, &t.Name, &t.Color, &t.TextColor, &t.CreatedAt); err != nil {
			return nil, err
		}
		m[userID] = append(m[userID], t)
	}
	return m, rows.Err()
}

// SetUserTagsForUser replaces the set of UserTags attached to a user.
func (d *DB) SetUserTagsForUser(userID uint64, userTagIDs []uint64) error {
	_, err := d.db.Exec("DELETE FROM user_tag_links WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	for _, tid := range userTagIDs {
		if _, err := d.db.Exec("INSERT INTO user_tag_links (user_id, user_tag_id) VALUES (?, ?)", userID, tid); err != nil {
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
		       last_error, next_run_at, schedule_description, config_json, updated_at,
		       bytes_total, bytes_new, files_total, files_new, snapshot_id,
		       repo_size_observed, repo_size_estimated, repo_size_observed_at,
		       error_category, repo_stats_interval_seconds, snapshot_count
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
			&j.BytesTotal, &j.BytesNew, &j.FilesTotal, &j.FilesNew, &j.SnapshotID,
			&j.RepoSizeObserved, &j.RepoSizeEstimated, &j.RepoSizeObservedAt,
			&j.ErrorCategory, &j.RepoStatsIntervalSec, &j.SnapshotCount,
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
	return d.UpsertJobSnapshotWithCategory(nodeID, job, "")
}

// UpsertJobSnapshotWithCategory lets the caller pass a pre-classified error_category.
// Pass "" and the existing category is preserved (or the caller can classify and pass the result).
func (d *DB) UpsertJobSnapshotWithCategory(nodeID uint64, job models.JobStatus, errorCategory string) error {
	// job.Config is populated only on heartbeat reports. On post_run reports
	// it's nil/empty — pass NULL so ON DUPLICATE KEY UPDATE's COALESCE
	// preserves whatever config the last heartbeat stored.
	var configArg interface{}
	if len(job.Config) > 0 && string(job.Config) != "null" {
		configArg = string(job.Config)
	}

	// Pull result fields (optional).
	var bytesTotal, bytesNew, filesTotal, filesNew uint64
	var snapshotID string
	var snapshotCount uint32
	var snapshotIDsArg interface{} // JSON or NULL
	if job.Result != nil {
		bytesTotal = job.Result.BytesTotal
		bytesNew = job.Result.BytesNew
		filesTotal = job.Result.FilesTotal
		filesNew = job.Result.FilesNew
		snapshotID = job.Result.SnapshotID
		snapshotCount = job.Result.SnapshotCount
		if len(job.Result.SnapshotIDs) > 0 {
			if b, err := json.Marshal(job.Result.SnapshotIDs); err == nil {
				snapshotIDsArg = string(b)
			}
		}
	}

	// If the CLI sent an authoritative repo size, mark it observed NOW and reset the estimate to match.
	// Otherwise: add bytes_new to the running estimate (handled in UPDATE clause).
	var repoSizeObservedArg, repoSizeObservedAtArg interface{}
	if job.RepoSizeBytes != nil {
		repoSizeObservedArg = *job.RepoSizeBytes
		repoSizeObservedAtArg = time.Now().UTC()
	}

	_, err := d.db.Exec(`
		INSERT INTO job_snapshots
		  (node_id, job_id, job_name, program, enabled, last_status,
		   last_run_at, last_run_duration_seconds, last_error, next_run_at,
		   schedule_description, config_json,
		   bytes_total, bytes_new, files_total, files_new, snapshot_id,
		   repo_size_observed, repo_size_estimated, repo_size_observed_at,
		   error_category, snapshot_count, snapshot_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
		        ?, ?, ?, ?, ?,
		        COALESCE(?, 0), COALESCE(?, 0), ?,
		        ?, ?, ?)
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
		  bytes_total               = VALUES(bytes_total),
		  bytes_new                 = VALUES(bytes_new),
		  files_total               = VALUES(files_total),
		  files_new                 = VALUES(files_new),
		  snapshot_id               = IF(VALUES(snapshot_id) <> '', VALUES(snapshot_id), snapshot_id),
		  repo_size_observed        = IF(? IS NOT NULL, VALUES(repo_size_observed), repo_size_observed),
		  repo_size_observed_at     = IF(? IS NOT NULL, VALUES(repo_size_observed_at), repo_size_observed_at),
		  repo_size_estimated       = IF(? IS NOT NULL, VALUES(repo_size_observed), repo_size_estimated + VALUES(bytes_new)),
		  error_category            = VALUES(error_category),
		  snapshot_count            = VALUES(snapshot_count),
		  snapshot_ids              = COALESCE(VALUES(snapshot_ids), snapshot_ids),
		  updated_at                = CURRENT_TIMESTAMP`,
		nodeID, job.ID, job.Name, job.Program, job.Enabled, job.LastStatus,
		job.LastRunAt, job.LastRunDurationSeconds, job.LastError, job.NextRunAt,
		job.ScheduleDescription, configArg,
		bytesTotal, bytesNew, filesTotal, filesNew, snapshotID,
		repoSizeObservedArg, repoSizeObservedArg, repoSizeObservedAtArg,
		errorCategory, snapshotCount, snapshotIDsArg,
		// args for the three IF(? IS NOT NULL, ...) checks in ON DUPLICATE KEY UPDATE:
		repoSizeObservedArg, repoSizeObservedAtArg, repoSizeObservedArg,
	)
	return err
}

// ─── Node reports ────────────────────────────────────────────────────────────

// ListRecentPostRunReports returns the most recent post_run payloads for a node
// (optionally within a date range). Used by the per-job history endpoint which
// parses the payload JSON to extract that specific job's state at each run.
func (d *DB) ListRecentPostRunReports(nodeID uint64, fromDate, toDate string, limit int) ([]*models.NodeReport, error) {
	args := []interface{}{nodeID}
	where := "WHERE node_id = ? AND report_type = 'post_run'"
	if fromDate != "" {
		where += " AND reported_at >= ?"
		args = append(args, fromDate)
	}
	if toDate != "" {
		where += " AND reported_at < DATE_ADD(?, INTERVAL 1 DAY)"
		args = append(args, toDate)
	}
	args = append(args, limit)
	rows, err := d.db.Query(`
		SELECT id, node_id, reported_at, received_at, report_type, payload_json
		FROM node_reports `+where+`
		ORDER BY reported_at DESC
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.NodeReport
	for rows.Next() {
		r := &models.NodeReport{}
		if err := rows.Scan(&r.ID, &r.NodeID, &r.ReportedAt, &r.ReceivedAt, &r.ReportType, &r.PayloadJSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

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
		q2 += " AND " + where[len(" WHERE "):]
	}
	if err := d.db.QueryRow(q2, args...).Scan(&stats.FailingNodes); err != nil {
		return nil, fmt.Errorf("dashboard failing counter: %w", err)
	}

	// Warning nodes: distinct nodes with at least one warning job snapshot (but not counted as failing).
	q3 := `
		SELECT COUNT(DISTINCT js.node_id)
		FROM job_snapshots js
		JOIN nodes n ON n.id = js.node_id
		WHERE js.last_status = 'warning'`
	if where != "" {
		q3 += " AND " + where[len(" WHERE "):]
	}
	if err := d.db.QueryRow(q3, args...).Scan(&stats.WarningNodes); err != nil {
		return nil, fmt.Errorf("dashboard warning counter: %w", err)
	}

	return stats, nil
}

// ListGroupsWithStats returns each client group with node count and worst job
// status. groupIDs is nil for superadmins (all groups). Single JOIN query, no
// per-group subqueries.
func (d *DB) ListGroupsWithStats(groupIDs []uint64) ([]*models.GroupWithStats, error) {
	query := `
		SELECT cg.id, cg.name, cg.rank, cg.created_at,
		       COUNT(DISTINCT n.id) AS node_count,
		       CASE
		         WHEN SUM(js.last_status = 'failure') > 0 THEN 'failure'
		         WHEN SUM(js.last_status = 'warning') > 0 THEN 'warning'
		         WHEN SUM(js.last_status = '')        > 0 THEN 'never_run'
		         WHEN SUM(js.last_status = 'success') > 0 THEN 'success'
		         ELSE ''
		       END AS worst_status,
		       COALESCE(SUM(js.last_status = 'success'), 0) AS success_jobs,
		       COALESCE(SUM(js.last_status = 'failure'), 0) AS failure_jobs,
		       COALESCE(SUM(js.last_status = 'warning'), 0) AS warning_jobs,
		       COALESCE(SUM(js.id IS NOT NULL AND js.last_status = ''), 0) AS never_run_jobs
		FROM client_groups cg
		LEFT JOIN nodes n          ON n.client_group_id = cg.id AND n.first_seen_at IS NOT NULL
		LEFT JOIN job_snapshots js ON js.node_id = n.id`
	args := []interface{}{}
	if len(groupIDs) > 0 {
		query += " WHERE cg.id IN (" + placeholders(len(groupIDs)) + ")"
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += " GROUP BY cg.id, cg.name, cg.rank, cg.created_at ORDER BY cg.name"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.GroupWithStats
	for rows.Next() {
		gws := &models.GroupWithStats{}
		if err := rows.Scan(
			&gws.ID, &gws.Name, &gws.Rank, &gws.CreatedAt, &gws.NodeCount, &gws.WorstStatus,
			&gws.SuccessJobs, &gws.FailureJobs, &gws.WarningJobs, &gws.NeverRunJobs,
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

// ─── Silences (per-job alert mute) ───────────────────────────────────────────

func (d *DB) GetJobSilence(nodeID uint64, jobID string) (*models.JobSilence, error) {
	s := &models.JobSilence{}
	var until sql.NullTime
	var createdBy sql.NullInt64
	err := d.db.QueryRow(`
		SELECT node_id, job_id, silenced_until, reason, created_by, created_at
		FROM job_silences WHERE node_id = ? AND job_id = ?`, nodeID, jobID).
		Scan(&s.NodeID, &s.JobID, &until, &s.Reason, &createdBy, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if until.Valid {
		s.SilencedUntil = &until.Time
	}
	if createdBy.Valid {
		v := uint64(createdBy.Int64)
		s.CreatedBy = &v
	}
	return s, nil
}

// SetJobSilence creates/updates a silence. Pass nil for silencedUntil to mean "forever".
func (d *DB) SetJobSilence(nodeID uint64, jobID string, silencedUntil *time.Time, reason string, createdBy uint64) error {
	_, err := d.db.Exec(`
		INSERT INTO job_silences (node_id, job_id, silenced_until, reason, created_by)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		  silenced_until = VALUES(silenced_until),
		  reason         = VALUES(reason),
		  created_by     = VALUES(created_by),
		  created_at     = CURRENT_TIMESTAMP`,
		nodeID, jobID, silencedUntil, reason, createdBy)
	return err
}

func (d *DB) DeleteJobSilence(nodeID uint64, jobID string) error {
	_, err := d.db.Exec("DELETE FROM job_silences WHERE node_id = ? AND job_id = ?", nodeID, jobID)
	return err
}

// GetAllActiveSilences returns a map keyed by "nodeID|jobID" of currently-active silences.
// Expired silences are filtered out.
func (d *DB) GetAllActiveSilences() (map[string]*models.JobSilence, error) {
	rows, err := d.db.Query(`
		SELECT node_id, job_id, silenced_until, reason, created_by, created_at
		FROM job_silences
		WHERE silenced_until IS NULL OR silenced_until > NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]*models.JobSilence)
	for rows.Next() {
		s := &models.JobSilence{}
		var until sql.NullTime
		var createdBy sql.NullInt64
		if err := rows.Scan(&s.NodeID, &s.JobID, &until, &s.Reason, &createdBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		if until.Valid {
			s.SilencedUntil = &until.Time
		}
		if createdBy.Valid {
			v := uint64(createdBy.Int64)
			s.CreatedBy = &v
		}
		out[fmt.Sprintf("%d|%s", s.NodeID, s.JobID)] = s
	}
	return out, rows.Err()
}

// ─── Job tags ────────────────────────────────────────────────────────────────

func (d *DB) ListJobTags() ([]*models.JobTag, error) {
	rows, err := d.db.Query("SELECT id, name, color, text_color, priority, created_at FROM job_tag_catalog ORDER BY priority DESC, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.JobTag
	for rows.Next() {
		t := &models.JobTag{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor, &t.Priority, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) CreateJobTag(name, color, textColor string, priority uint8) (uint64, error) {
	if color == "" {
		color = "#206bc4"
	}
	if textColor == "" {
		textColor = "#f0f0f0"
	}
	res, err := d.db.Exec("INSERT INTO job_tag_catalog (name, color, text_color, priority) VALUES (?, ?, ?, ?)", name, color, textColor, priority)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateJobTag(id uint64, name, color, textColor string, priority uint8) error {
	_, err := d.db.Exec("UPDATE job_tag_catalog SET name = ?, color = ?, text_color = ?, priority = ? WHERE id = ?", name, color, textColor, priority, id)
	return err
}

func (d *DB) DeleteJobTag(id uint64) error {
	_, err := d.db.Exec("DELETE FROM job_tag_catalog WHERE id = ?", id)
	return err
}

// GetJobTags returns tags for a specific (node, job).
func (d *DB) GetJobTags(nodeID uint64, jobID string) ([]models.JobTag, error) {
	rows, err := d.db.Query(`
		SELECT c.id, c.name, c.color, c.text_color, c.priority, c.created_at
		FROM job_tag_catalog c
		JOIN job_tag_links l ON l.job_tag_id = c.id
		WHERE l.node_id = ? AND l.job_id = ?
		ORDER BY c.priority DESC, c.name`, nodeID, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.JobTag
	for rows.Next() {
		t := models.JobTag{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.TextColor, &t.Priority, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) SetJobTags(nodeID uint64, jobID string, tagIDs []uint64) error {
	if _, err := d.db.Exec("DELETE FROM job_tag_links WHERE node_id = ? AND job_id = ?", nodeID, jobID); err != nil {
		return err
	}
	for _, tid := range tagIDs {
		if _, err := d.db.Exec("INSERT INTO job_tag_links (node_id, job_id, job_tag_id) VALUES (?, ?, ?)", nodeID, jobID, tid); err != nil {
			return err
		}
	}
	return nil
}

// ─── Retention / aggregation worker helpers ──────────────────────────────────

// AggregateDailyStats rolls up node_reports beyond `cutoffDays` into job_daily_stats.
// Returns rows aggregated.
func (d *DB) AggregateDailyStats(cutoffDays uint32) (int64, error) {
	// Aggregate post_run reports older than cutoffDays into job_daily_stats.
	// Reports are JSON, so we rely on job_snapshots having historical last_run per day?
	// Simpler: aggregate from job_snapshots current state per day based on last_run_at.
	// This is a rough aggregation — it records at least one "run per day per job".
	res, err := d.db.Exec(`
		INSERT INTO job_daily_stats (node_id, job_id, day, runs, successes, warnings, failures, skipped, total_duration_s, bytes_new_sum, worst_error_cat)
		SELECT node_id, job_id, DATE(last_run_at),
		       1,
		       IF(last_status='success',1,0),
		       IF(last_status='warning',1,0),
		       IF(last_status='failure',1,0),
		       IF(last_status='skipped',1,0),
		       last_run_duration_seconds,
		       bytes_new,
		       error_category
		FROM job_snapshots
		WHERE last_run_at IS NOT NULL
		  AND last_run_at < DATE_SUB(NOW(), INTERVAL ? DAY)
		ON DUPLICATE KEY UPDATE
		  runs             = runs + 1,
		  successes        = successes + VALUES(successes),
		  warnings         = warnings + VALUES(warnings),
		  failures         = failures + VALUES(failures),
		  skipped          = skipped + VALUES(skipped),
		  total_duration_s = total_duration_s + VALUES(total_duration_s),
		  bytes_new_sum    = bytes_new_sum + VALUES(bytes_new_sum),
		  worst_error_cat  = IF(VALUES(worst_error_cat) <> '', VALUES(worst_error_cat), worst_error_cat)`,
		cutoffDays)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneHeartbeatReports deletes heartbeat-type reports older than cutoffDays.
func (d *DB) PruneHeartbeatReports(cutoffDays uint32) (int64, error) {
	res, err := d.db.Exec(`
		DELETE FROM node_reports
		WHERE report_type = 'heartbeat'
		  AND reported_at < DATE_SUB(NOW(), INTERVAL ? DAY)`, cutoffDays)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneAllReports deletes any node_reports older than cutoffDays.
func (d *DB) PruneAllReports(cutoffDays uint32) (int64, error) {
	res, err := d.db.Exec(`
		DELETE FROM node_reports
		WHERE reported_at < DATE_SUB(NOW(), INTERVAL ? DAY)`, cutoffDays)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ─── Server tuning ───────────────────────────────────────────────────────────

func (d *DB) GetServerTuning() (*models.ServerTuning, error) {
	t := &models.ServerTuning{}
	err := d.db.QueryRow(`
		SELECT repo_stats_interval_seconds, repo_stats_timeout_seconds,
		       retention_raw_days, retention_post_run_days,
		       offline_threshold_minutes, offline_check_interval_minutes,
		       default_silence_seconds,
		       anomaly_snapshot_drop_threshold, anomaly_files_drop_pct, anomaly_files_drop_min,
		       anomaly_bytes_drop_pct, anomaly_bytes_drop_min_mb,
		       anomaly_ack_retention_days, audit_retention_days,
		       terminal_recording_enabled, terminal_recording_retention_days,
		       silent_alert_threshold_minutes,
		       latest_cli_version, latest_cli_version_checked_at,
		       update_check_interval_minutes,
		       latest_server_version, latest_server_version_checked_at,
		       server_backup_enabled, server_backup_interval_hours,
		       server_backup_last_at, server_backup_last_status, COALESCE(server_backup_last_error, '')
		FROM server_tuning WHERE id = 1`).
		Scan(&t.RepoStatsIntervalSeconds, &t.RepoStatsTimeoutSeconds,
			&t.RetentionRawDays, &t.RetentionPostRunDays,
			&t.OfflineThresholdMinutes, &t.OfflineCheckIntervalMinutes,
			&t.DefaultSilenceSeconds,
			&t.AnomalySnapshotDropThreshold, &t.AnomalyFilesDropPct, &t.AnomalyFilesDropMin,
			&t.AnomalyBytesDropPct, &t.AnomalyBytesDropMinMB,
			&t.AnomalyAckRetentionDays, &t.AuditRetentionDays,
			&t.TerminalRecordingEnabled, &t.TerminalRecordingRetentionDays,
			&t.SilentAlertThresholdMinutes,
			&t.LatestCLIVersion, &t.LatestCLIVersionCheckedAt,
			&t.UpdateCheckIntervalMinutes,
			&t.LatestServerVersion, &t.LatestServerVersionCheckedAt,
			&t.ServerBackupEnabled, &t.ServerBackupIntervalHours,
			&t.ServerBackupLastAt, &t.ServerBackupLastStatus, &t.ServerBackupLastError)
	if errors.Is(err, sql.ErrNoRows) {
		return &models.ServerTuning{
			RepoStatsIntervalSeconds:     86400,
			RepoStatsTimeoutSeconds:      300,
			RetentionRawDays:             7,
			RetentionPostRunDays:         30,
			OfflineThresholdMinutes:      10,
			OfflineCheckIntervalMinutes:  5,
			DefaultSilenceSeconds:        3600,
			AnomalySnapshotDropThreshold: 1,
			AnomalyFilesDropPct:          5,
			AnomalyFilesDropMin:          10,
			AnomalyBytesDropPct:          10,
			AnomalyBytesDropMinMB:        100,
			AnomalyAckRetentionDays:        30,
			AuditRetentionDays:             0,
			TerminalRecordingEnabled:       true,
			TerminalRecordingRetentionDays: 30,
			SilentAlertThresholdMinutes:    7,
			UpdateCheckIntervalMinutes:     30,
			ServerBackupEnabled:            true,
			ServerBackupIntervalHours:      24,
		}, nil
	}
	return t, err
}

func (d *DB) UpdateServerTuning(t *models.ServerTuning) error {
	_, err := d.db.Exec(`
		UPDATE server_tuning SET
		  repo_stats_interval_seconds    = ?,
		  repo_stats_timeout_seconds     = ?,
		  retention_raw_days             = ?,
		  retention_post_run_days        = ?,
		  offline_threshold_minutes      = ?,
		  offline_check_interval_minutes = ?,
		  default_silence_seconds        = ?,
		  anomaly_snapshot_drop_threshold = ?,
		  anomaly_files_drop_pct         = ?,
		  anomaly_files_drop_min         = ?,
		  anomaly_bytes_drop_pct         = ?,
		  anomaly_bytes_drop_min_mb      = ?,
		  anomaly_ack_retention_days     = ?,
		  audit_retention_days           = ?,
		  terminal_recording_enabled      = ?,
		  terminal_recording_retention_days = ?,
		  silent_alert_threshold_minutes  = ?,
		  update_check_interval_minutes  = ?
		WHERE id = 1`,
		t.RepoStatsIntervalSeconds, t.RepoStatsTimeoutSeconds,
		t.RetentionRawDays, t.RetentionPostRunDays,
		t.OfflineThresholdMinutes, t.OfflineCheckIntervalMinutes,
		t.DefaultSilenceSeconds,
		t.AnomalySnapshotDropThreshold, t.AnomalyFilesDropPct, t.AnomalyFilesDropMin,
		t.AnomalyBytesDropPct, t.AnomalyBytesDropMinMB,
		t.AnomalyAckRetentionDays, t.AuditRetentionDays,
		t.TerminalRecordingEnabled, t.TerminalRecordingRetentionDays,
		t.SilentAlertThresholdMinutes,
		t.UpdateCheckIntervalMinutes)
	return err
}

// ─── Anomaly detection ──────────────────────────────────────────────────────

// GetJobSnapshotPrev returns the current job_snapshots row (BEFORE we upsert) so
// we can compute deltas. Returns nil if not found.
func (d *DB) GetJobSnapshotPrev(nodeID uint64, jobID string) (*models.JobSnapshot, error) {
	rows, err := d.db.Query(`
		SELECT id, node_id, job_id, job_name, program, enabled,
		       last_status, last_run_at, last_run_duration_seconds,
		       last_error, next_run_at, schedule_description, config_json, updated_at,
		       bytes_total, bytes_new, files_total, files_new, snapshot_id,
		       repo_size_observed, repo_size_estimated, repo_size_observed_at,
		       error_category, repo_stats_interval_seconds, snapshot_count,
		       snapshot_ids
		FROM job_snapshots WHERE node_id = ? AND job_id = ? LIMIT 1`, nodeID, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	j := &models.JobSnapshot{}
	var config sql.NullString
	var sids sql.NullString
	if err := rows.Scan(
		&j.ID, &j.NodeID, &j.JobID, &j.JobName, &j.Program, &j.Enabled,
		&j.LastStatus, &j.LastRunAt, &j.LastRunDurationSeconds,
		&j.LastError, &j.NextRunAt, &j.ScheduleDescription, &config, &j.UpdatedAt,
		&j.BytesTotal, &j.BytesNew, &j.FilesTotal, &j.FilesNew, &j.SnapshotID,
		&j.RepoSizeObserved, &j.RepoSizeEstimated, &j.RepoSizeObservedAt,
		&j.ErrorCategory, &j.RepoStatsIntervalSec, &j.SnapshotCount,
		&sids,
	); err != nil {
		return nil, err
	}
	if config.Valid {
		j.ConfigJSON = config.String
	}
	if sids.Valid && sids.String != "" {
		_ = json.Unmarshal([]byte(sids.String), &j.SnapshotIDs)
	}
	return j, nil
}

// InsertJobAnomaly creates a new anomaly row, but skips if an unacknowledged
// anomaly of the same (node, job, type) already exists in the last 24h.
// Prevents alert spam from re-reported pre-wipe state.
func (d *DB) InsertJobAnomaly(a *models.JobAnomaly) error {
	var dupCount int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM job_anomalies
		WHERE node_id = ? AND job_id = ? AND anomaly_type = ?
		  AND acknowledged = 0
		  AND detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
		a.NodeID, a.JobID, string(a.AnomalyType)).Scan(&dupCount)
	if err != nil {
		return err
	}
	if dupCount > 0 {
		return nil // dedup — already an open alert
	}
	_, err = d.db.Exec(`
		INSERT INTO job_anomalies
		  (node_id, job_id, anomaly_type, prev_value, curr_value, delta_value, delta_pct,
		   snapshot_id, prev_snapshot_id, curr_snapshot_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.NodeID, a.JobID, string(a.AnomalyType), a.PrevValue, a.CurrValue, a.DeltaValue, a.DeltaPct,
		a.SnapshotID, a.PrevSnapshotID, a.CurrSnapshotID)
	return err
}

// ListJobAnomalies returns recent anomalies, optionally filtered.
func (d *DB) ListJobAnomalies(nodeID uint64, jobID string, onlyUnacked bool, limit int) ([]*models.JobAnomaly, error) {
	args := []interface{}{}
	where := "WHERE 1=1"
	if nodeID > 0 {
		where += " AND node_id = ?"
		args = append(args, nodeID)
	}
	if jobID != "" {
		where += " AND job_id = ?"
		args = append(args, jobID)
	}
	if onlyUnacked {
		where += " AND acknowledged = 0"
	}
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := d.db.Query(`
		SELECT id, node_id, job_id, detected_at, anomaly_type, prev_value, curr_value,
		       delta_value, delta_pct, snapshot_id, acknowledged, acknowledged_by, acknowledged_at,
		       COALESCE(resolution_note, ''),
		       COALESCE(prev_snapshot_id, ''), COALESCE(curr_snapshot_id, '')
		FROM job_anomalies `+where+`
		ORDER BY detected_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.JobAnomaly
	for rows.Next() {
		a := &models.JobAnomaly{}
		var atype string
		var ackedBy sql.NullInt64
		var ackedAt sql.NullTime
		var acked int
		if err := rows.Scan(&a.ID, &a.NodeID, &a.JobID, &a.DetectedAt, &atype, &a.PrevValue, &a.CurrValue,
			&a.DeltaValue, &a.DeltaPct, &a.SnapshotID, &acked, &ackedBy, &ackedAt, &a.ResolutionNote,
			&a.PrevSnapshotID, &a.CurrSnapshotID); err != nil {
			return nil, err
		}
		a.AnomalyType = models.AnomalyType(atype)
		a.Acknowledged = acked != 0
		if ackedBy.Valid {
			v := uint64(ackedBy.Int64)
			a.AcknowledgedBy = &v
		}
		if ackedAt.Valid {
			t := ackedAt.Time
			a.AcknowledgedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAnomalyTarget returns (node_id, job_id) for an anomaly row — needed when
// the ack flow optionally creates a silence on the same (node, job) pair.
func (d *DB) GetAnomalyTarget(id uint64) (uint64, string, error) {
	var nodeID uint64
	var jobID string
	err := d.db.QueryRow("SELECT node_id, job_id FROM job_anomalies WHERE id = ?", id).Scan(&nodeID, &jobID)
	return nodeID, jobID, err
}

func (d *DB) AcknowledgeAnomaly(id uint64, userID uint64, note string) error {
	if len(note) > 500 {
		note = note[:497] + "…"
	}
	_, err := d.db.Exec(
		"UPDATE job_anomalies SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = NOW(), resolution_note = ? WHERE id = ?",
		userID, note, id)
	return err
}

func (d *DB) UnacknowledgeAnomaly(id uint64) error {
	_, err := d.db.Exec(
		"UPDATE job_anomalies SET acknowledged = 0, acknowledged_by = NULL, acknowledged_at = NULL, resolution_note = '' WHERE id = ?", id)
	return err
}

func (d *DB) CountUnackedAnomalies() (int, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM job_anomalies WHERE acknowledged = 0").Scan(&n)
	return n, err
}

// CountUnackedAnomaliesByJob returns the count of unacknowledged anomalies grouped by job_id for a node.
func (d *DB) CountUnackedAnomaliesByJob(nodeID uint64) (map[string]int, error) {
	rows, err := d.db.Query(`
		SELECT job_id, COUNT(*) FROM job_anomalies
		WHERE node_id = ? AND acknowledged = 0
		GROUP BY job_id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var jid string
		var n int
		if err := rows.Scan(&jid, &n); err != nil {
			return nil, err
		}
		out[jid] = n
	}
	return out, rows.Err()
}

// EnrichedAnomaly is an anomaly with display labels for the node and client.
type EnrichedAnomaly struct {
	*models.JobAnomaly
	NodeName       string
	NodeUID        string
	ClientID       uint64
	ClientName     string
	JobName        string
	JobProgram     string
	AckedByName    string
}

// ListEnrichedAnomalies joins anomalies with node + client info for the global Security page.
// filter: "" or "all" → all, "ack" → only acknowledged, "unack" → only unacknowledged.
// mode:
//   - "live" (archiveDays > 0): excludes acked rows older than N days (those live on the archive page).
//   - "archive" (archiveDays > 0): ONLY returns acked rows older than N days.
//   - "all" (archiveDays = 0): returns everything regardless of age.
func (d *DB) ListEnrichedAnomalies(filter string, archiveDays uint32, archiveOnly bool, limit int) ([]*EnrichedAnomaly, error) {
	if limit <= 0 {
		limit = 200
	}
	var conds []string
	var args []interface{}
	switch filter {
	case "ack":
		conds = append(conds, "a.acknowledged = 1")
	case "unack":
		conds = append(conds, "a.acknowledged = 0")
	}
	if archiveDays > 0 {
		if archiveOnly {
			conds = append(conds, "a.acknowledged = 1 AND a.acknowledged_at IS NOT NULL AND a.acknowledged_at < DATE_SUB(NOW(), INTERVAL ? DAY)")
			args = append(args, archiveDays)
		} else {
			conds = append(conds, "(a.acknowledged = 0 OR a.acknowledged_at IS NULL OR a.acknowledged_at >= DATE_SUB(NOW(), INTERVAL ? DAY))")
			args = append(args, archiveDays)
		}
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	rows, err := d.db.Query(`
		SELECT a.id, a.node_id, a.job_id, a.detected_at, a.anomaly_type, a.prev_value, a.curr_value,
		       a.delta_value, a.delta_pct, a.snapshot_id, a.acknowledged, a.acknowledged_by, a.acknowledged_at,
		       COALESCE(a.resolution_note, ''),
		       COALESCE(a.prev_snapshot_id, ''), COALESCE(a.curr_snapshot_id, ''),
		       n.name, n.uid, n.client_group_id, COALESCE(c.name, ''),
		       COALESCE(j.job_name, ''), COALESCE(j.program, ''),
		       COALESCE(u.username, '')
		FROM job_anomalies a
		JOIN nodes n             ON n.id = a.node_id
		LEFT JOIN client_groups c ON c.id = n.client_group_id
		LEFT JOIN job_snapshots j ON j.node_id = a.node_id AND j.job_id = a.job_id
		LEFT JOIN users u         ON u.id = a.acknowledged_by
		`+where+`
		ORDER BY a.detected_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EnrichedAnomaly
	for rows.Next() {
		ea := &EnrichedAnomaly{JobAnomaly: &models.JobAnomaly{}}
		var atype string
		var ackedBy sql.NullInt64
		var ackedAt sql.NullTime
		var acked int
		if err := rows.Scan(&ea.JobAnomaly.ID, &ea.JobAnomaly.NodeID, &ea.JobAnomaly.JobID, &ea.JobAnomaly.DetectedAt,
			&atype, &ea.JobAnomaly.PrevValue, &ea.JobAnomaly.CurrValue,
			&ea.JobAnomaly.DeltaValue, &ea.JobAnomaly.DeltaPct, &ea.JobAnomaly.SnapshotID,
			&acked, &ackedBy, &ackedAt, &ea.JobAnomaly.ResolutionNote,
			&ea.JobAnomaly.PrevSnapshotID, &ea.JobAnomaly.CurrSnapshotID,
			&ea.NodeName, &ea.NodeUID, &ea.ClientID, &ea.ClientName,
			&ea.JobName, &ea.JobProgram, &ea.AckedByName); err != nil {
			return nil, err
		}
		ea.JobAnomaly.AnomalyType = models.AnomalyType(atype)
		ea.JobAnomaly.Acknowledged = acked != 0
		if ackedBy.Valid {
			v := uint64(ackedBy.Int64)
			ea.JobAnomaly.AcknowledgedBy = &v
		}
		if ackedAt.Valid {
			t := ackedAt.Time
			ea.JobAnomaly.AcknowledgedAt = &t
		}
		out = append(out, ea)
	}
	return out, rows.Err()
}

// JobsNeedingRepoStats returns the job_ids for a node where repo stats are stale
// per the global default interval (with per-job override respected if non-zero).
// A job needs stats if: repo_size_observed_at IS NULL  OR  age > effective interval.
func (d *DB) JobsNeedingRepoStats(nodeID uint64, globalIntervalSec uint32) ([]string, error) {
	// Effective interval = per-job override if set, else global.
	rows, err := d.db.Query(`
		SELECT job_id
		FROM job_snapshots
		WHERE node_id = ?
		  AND enabled = 1
		  AND program = 'restic'
		  AND (
		    repo_size_observed_at IS NULL
		    OR TIMESTAMPDIFF(SECOND, repo_size_observed_at, NOW()) >
		       IF(repo_stats_interval_seconds > 0, repo_stats_interval_seconds, ?)
		  )`, nodeID, globalIntervalSec)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ─── Permissions (unified rule engine) ───────────────────────────────────────

// ListPermissionRules returns all rules sorted by priority DESC.
func (d *DB) ListPermissionRules() ([]*models.PermissionRule, error) {
	rows, err := d.db.Query(`
		SELECT id, priority, enabled, effect, access, subject_type, subject_id, target_type, target_id,
		       locked_by_superadmin, created_by, created_at
		FROM permission_rules
		ORDER BY priority DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.PermissionRule
	for rows.Next() {
		r := &models.PermissionRule{}
		var enabled, locked int
		var createdBy sql.NullInt64
		var effect, access, subjectType, targetType string
		if err := rows.Scan(&r.ID, &r.Priority, &enabled, &effect, &access, &subjectType, &r.SubjectID,
			&targetType, &r.TargetID, &locked, &createdBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.Effect = models.Effect(effect)
		r.Access = models.AccessLevel(access)
		r.SubjectType = models.SubjectType(subjectType)
		r.TargetType = models.TargetType(targetType)
		r.LockedBySuperadmin = locked != 0
		if createdBy.Valid {
			v := uint64(createdBy.Int64)
			r.CreatedBy = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreatePermissionRule inserts a new rule.
func (d *DB) CreatePermissionRule(r *models.PermissionRule) (uint64, error) {
	lockedInt := 0
	if r.LockedBySuperadmin {
		lockedInt = 1
	}
	enabledInt := 1
	if !r.Enabled {
		enabledInt = 0
	}
	var createdBy sql.NullInt64
	if r.CreatedBy != nil {
		createdBy = sql.NullInt64{Int64: int64(*r.CreatedBy), Valid: true}
	}
	res, err := d.db.Exec(`
		INSERT INTO permission_rules (priority, enabled, effect, access, subject_type, subject_id, target_type, target_id, locked_by_superadmin, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Priority, enabledInt, string(r.Effect), string(r.Access), string(r.SubjectType), r.SubjectID,
		string(r.TargetType), r.TargetID, lockedInt, createdBy)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

// UpdatePermissionRule overwrites a rule's mutable fields.
func (d *DB) UpdatePermissionRule(r *models.PermissionRule) error {
	lockedInt := 0
	if r.LockedBySuperadmin {
		lockedInt = 1
	}
	enabledInt := 1
	if !r.Enabled {
		enabledInt = 0
	}
	_, err := d.db.Exec(`
		UPDATE permission_rules
		SET priority = ?, enabled = ?, effect = ?, access = ?, subject_type = ?, subject_id = ?,
		    target_type = ?, target_id = ?, locked_by_superadmin = ?
		WHERE id = ?`,
		r.Priority, enabledInt, string(r.Effect), string(r.Access), string(r.SubjectType), r.SubjectID,
		string(r.TargetType), r.TargetID, lockedInt, r.ID)
	return err
}

// SetPermissionRuleEnabled toggles the enabled flag on a rule.
func (d *DB) SetPermissionRuleEnabled(id uint64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := d.db.Exec("UPDATE permission_rules SET enabled = ? WHERE id = ?", v, id)
	return err
}

// DeletePermissionRule removes a rule by ID.
func (d *DB) DeletePermissionRule(id uint64) error {
	_, err := d.db.Exec("DELETE FROM permission_rules WHERE id = ?", id)
	return err
}

// GetEffectiveUserTagIDs returns the union of a user's own tags and tags inherited from groups.
func (d *DB) GetEffectiveUserTagIDs(userID uint64) ([]uint64, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT user_tag_id FROM (
			SELECT user_tag_id FROM user_tag_links WHERE user_id = ?
			UNION
			SELECT ugt.user_tag_id FROM user_group_tags ugt
			JOIN user_group_members ugm ON ugm.user_group_id = ugt.user_group_id
			WHERE ugm.user_id = ?
		) AS t`, userID, userID)
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

// ListVisibleNodeIDsForUser returns, for a user (non-superadmin), the map of visible nodes → effective access.
// Evaluation: client scope first, then unified rule engine (priority DESC, allow/deny), capped elsewhere by role.
func (d *DB) ListVisibleNodeIDsForUser(userID uint64) (map[uint64]models.AccessLevel, error) {
	// Client scope: user's allowed client_group_ids.
	clientIDs, err := d.GetUserClientGroupIDs(userID)
	if err != nil {
		return nil, err
	}
	if len(clientIDs) == 0 {
		return map[uint64]models.AccessLevel{}, nil
	}

	// Build subject sets: user ID, group IDs, effective tag IDs.
	userGroupIDs, err := d.getUserGroupIDsForUser(userID)
	if err != nil {
		return nil, err
	}
	userTagIDs, err := d.GetEffectiveUserTagIDs(userID)
	if err != nil {
		return nil, err
	}

	// All rules, sorted priority DESC (already by query).
	rules, err := d.ListPermissionRules()
	if err != nil {
		return nil, err
	}

	// Index nodes by client scope, then gather their tags.
	nodes, err := d.listNodeIDsInClients(clientIDs)
	if err != nil {
		return nil, err
	}
	tagsByNode, err := d.getNodeTagIDsByNode(nodes)
	if err != nil {
		return nil, err
	}

	result := make(map[uint64]models.AccessLevel, len(nodes))
	for _, nid := range nodes {
		result[nid] = evaluateRulesForNode(rules, userID, userGroupIDs, userTagIDs, nid, tagsByNode[nid])
	}
	return result, nil
}

// evaluateRulesForNode walks sorted rules (priority DESC) and returns the effective AccessLevel
// for a single node. Default: none.
func evaluateRulesForNode(rules []*models.PermissionRule, userID uint64, groupIDs, userTagIDs []uint64, nodeID uint64, nodeTagIDs []uint64) models.AccessLevel {
	groupSet := uint64Set(groupIDs)
	userTagSet := uint64Set(userTagIDs)
	nodeTagSet := uint64Set(nodeTagIDs)

	// Start at "none" and upgrade based on the highest-priority non-deny rule.
	// Because rules are already sorted priority DESC, we walk twice: once for manage, once for view.
	// Higher priority wins; ties broken by earlier creation (id ASC).
	decide := func(requested models.AccessLevel) models.AccessLevel {
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			if !ruleSubjectMatches(r, userID, groupSet, userTagSet) {
				continue
			}
			if !ruleTargetMatches(r, nodeID, nodeTagSet) {
				continue
			}
			switch r.Effect {
			case models.EffectAllow:
				// allow with access >= requested grants
				if accessGE(r.Access, requested) {
					return requested
				}
			case models.EffectDeny:
				// deny with access <= requested denies
				if accessLE(r.Access, requested) {
					return models.AccessNone
				}
			}
		}
		return models.AccessNone
	}

	// Prefer manage if granted, else view.
	if decide(models.AccessManage) == models.AccessManage {
		return models.AccessManage
	}
	if decide(models.AccessView) == models.AccessView {
		return models.AccessView
	}
	return models.AccessNone
}

func accessGE(a, b models.AccessLevel) bool {
	// manage >= view >= none
	order := map[models.AccessLevel]int{models.AccessNone: 0, models.AccessView: 1, models.AccessManage: 2}
	return order[a] >= order[b]
}
func accessLE(a, b models.AccessLevel) bool {
	order := map[models.AccessLevel]int{models.AccessNone: 0, models.AccessView: 1, models.AccessManage: 2}
	return order[a] <= order[b]
}

func ruleSubjectMatches(r *models.PermissionRule, userID uint64, groupSet, userTagSet map[uint64]bool) bool {
	switch r.SubjectType {
	case models.SubjectUser:
		return r.SubjectID == userID
	case models.SubjectUserGroup:
		return groupSet[r.SubjectID]
	case models.SubjectUserTag:
		return userTagSet[r.SubjectID]
	}
	return false
}

func ruleTargetMatches(r *models.PermissionRule, nodeID uint64, nodeTagSet map[uint64]bool) bool {
	switch r.TargetType {
	case models.TargetNode:
		return r.TargetID == nodeID
	case models.TargetNodeTag:
		return nodeTagSet[r.TargetID]
	}
	return false
}

func uint64Set(s []uint64) map[uint64]bool {
	m := make(map[uint64]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// getUserGroupIDsForUser returns the IDs of user groups the user is a member of.
func (d *DB) getUserGroupIDsForUser(userID uint64) ([]uint64, error) {
	rows, err := d.db.Query("SELECT user_group_id FROM user_group_members WHERE user_id = ?", userID)
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

// listNodeIDsInClients returns node IDs belonging to any of the given client groups.
func (d *DB) listNodeIDsInClients(clientIDs []uint64) ([]uint64, error) {
	if len(clientIDs) == 0 {
		return nil, nil
	}
	q := "SELECT id FROM nodes WHERE client_group_id IN (" + placeholders(len(clientIDs)) + ")"
	args := uint64SliceToInterfaces(clientIDs)
	rows, err := d.db.Query(q, args...)
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

// getNodeTagIDsByNode returns tag IDs for each node id, keyed by node id.
func (d *DB) getNodeTagIDsByNode(nodeIDs []uint64) (map[uint64][]uint64, error) {
	result := make(map[uint64][]uint64)
	if len(nodeIDs) == 0 {
		return result, nil
	}
	q := "SELECT node_id, tag_id FROM node_tags WHERE node_id IN (" + placeholders(len(nodeIDs)) + ")"
	args := uint64SliceToInterfaces(nodeIDs)
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nid, tid uint64
		if err := rows.Scan(&nid, &tid); err != nil {
			return nil, err
		}
		result[nid] = append(result[nid], tid)
	}
	return result, rows.Err()
}

func uint64SliceToInterfaces(s []uint64) []interface{} {
	out := make([]interface{}, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// ─── User Groups ─────────────────────────────────────────────────────────────

func (d *DB) ListUserGroups() ([]*models.UserGroup, error) {
	rows, err := d.db.Query("SELECT id, name, client_group_id, created_at FROM user_groups ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.UserGroup
	for rows.Next() {
		g := &models.UserGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.ClientGroupID, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (d *DB) GetUserGroupByID(id uint64) (*models.UserGroup, error) {
	g := &models.UserGroup{}
	err := d.db.QueryRow("SELECT id, name, client_group_id, created_at FROM user_groups WHERE id = ?", id).
		Scan(&g.ID, &g.Name, &g.ClientGroupID, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (d *DB) CreateUserGroup(name string, clientGroupID uint64) (uint64, error) {
	res, err := d.db.Exec("INSERT INTO user_groups (name, client_group_id) VALUES (?, ?)", name, clientGroupID)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

func (d *DB) UpdateUserGroup(id uint64, name string, clientGroupID uint64) error {
	_, err := d.db.Exec("UPDATE user_groups SET name = ?, client_group_id = ? WHERE id = ?", name, clientGroupID, id)
	return err
}

func (d *DB) DeleteUserGroup(id uint64) error {
	_, err := d.db.Exec("DELETE FROM user_groups WHERE id = ?", id)
	return err
}

func (d *DB) GetUserGroupMembers(groupID uint64) ([]*models.UserGroupMember, error) {
	rows, err := d.db.Query("SELECT user_group_id, user_id, is_lead FROM user_group_members WHERE user_group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.UserGroupMember
	for rows.Next() {
		m := &models.UserGroupMember{}
		var lead int
		if err := rows.Scan(&m.UserGroupID, &m.UserID, &lead); err != nil {
			return nil, err
		}
		m.IsLead = lead != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) SetUserGroupMembers(groupID uint64, members []models.UserGroupMember) error {
	if _, err := d.db.Exec("DELETE FROM user_group_members WHERE user_group_id = ?", groupID); err != nil {
		return err
	}
	for _, m := range members {
		lead := 0
		if m.IsLead {
			lead = 1
		}
		if _, err := d.db.Exec("INSERT INTO user_group_members (user_group_id, user_id, is_lead) VALUES (?, ?, ?)",
			groupID, m.UserID, lead); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) GetUserGroupTagIDs(groupID uint64) ([]uint64, error) {
	rows, err := d.db.Query("SELECT user_tag_id FROM user_group_tags WHERE user_group_id = ?", groupID)
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

func (d *DB) SetUserGroupTags(groupID uint64, tagIDs []uint64) error {
	if _, err := d.db.Exec("DELETE FROM user_group_tags WHERE user_group_id = ?", groupID); err != nil {
		return err
	}
	for _, tid := range tagIDs {
		if _, err := d.db.Exec("INSERT INTO user_group_tags (user_group_id, user_tag_id) VALUES (?, ?)", groupID, tid); err != nil {
			return err
		}
	}
	return nil
}

// UpdateNodeCLIVersion sets the cli_version for a node.
func (d *DB) UpdateNodeCLIVersion(nodeID uint64, version string) error {
	_, err := d.db.Exec("UPDATE nodes SET cli_version = ? WHERE id = ?", version, nodeID)
	return err
}

// SetNodeCLIUpdatePending sets or clears the cli_update_pending flag.
func (d *DB) SetNodeCLIUpdatePending(nodeID uint64, pending bool) error {
	_, err := d.db.Exec("UPDATE nodes SET cli_update_pending = ? WHERE id = ?", pending, nodeID)
	return err
}

// SetLatestCLIVersion caches the latest known CLI version from GitHub.
func (d *DB) SetLatestCLIVersion(version string) error {
	_, err := d.db.Exec("UPDATE server_tuning SET latest_cli_version = ?, latest_cli_version_checked_at = NOW() WHERE id = 1", version)
	return err
}

// SetLatestServerVersion caches the latest known server version from GitHub.
func (d *DB) SetLatestServerVersion(version string) error {
	_, err := d.db.Exec("UPDATE server_tuning SET latest_server_version = ?, latest_server_version_checked_at = NOW() WHERE id = 1", version)
	return err
}

