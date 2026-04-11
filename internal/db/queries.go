package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	u := &models.User{}
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserByID(id uint64) (*models.User, error) {
	u := &models.User{}
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) ListUsers() ([]*models.User, error) {
	rows, err := d.db.Query(
		"SELECT id, username, password_hash, role, created_at, updated_at FROM users ORDER BY username",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
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
		"SELECT token, user_id, expires_at, created_at FROM sessions WHERE token = ?",
		token,
	).Scan(&s.Token, &s.UserID, &s.ExpiresAt, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return s, err
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
	err := d.db.QueryRow(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at, n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.uid = ?`, uid).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

func (d *DB) GetNodeByID(id uint64) (*models.Node, error) {
	n := &models.Node{}
	err := d.db.QueryRow(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at, n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.id = ?`, id).
		Scan(&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return n, err
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

// ListNodesWithStatus returns all nodes visible to the user, enriched with job
// count and worst job status. groupIDs is nil for superadmins (all nodes).
func (d *DB) ListNodesWithStatus(groupIDs []uint64) ([]*models.NodeWithStatus, error) {
	query := `
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at, n.created_at
		FROM nodes n
		JOIN client_groups cg ON cg.id = n.client_group_id`
	args := []interface{}{}
	if len(groupIDs) > 0 {
		query += " WHERE n.client_group_id IN (" + placeholders(len(groupIDs)) + ")"
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += " ORDER BY n.name"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeWithStatus
	for rows.Next() {
		ns := &models.NodeWithStatus{}
		if err := rows.Scan(
			&ns.ID, &ns.UID, &ns.Name, &ns.ClientGroupID, &ns.ClientGroup,
			&ns.PSKEncrypted, &ns.FirstSeenAt, &ns.LastSeenAt, &ns.CreatedAt,
		); err != nil {
			return nil, err
		}
		nodes = append(nodes, ns)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Enrich with job snapshots
	for _, ns := range nodes {
		jobs, err := d.ListJobSnapshots(ns.ID)
		if err != nil {
			return nil, err
		}
		ns.JobCount = len(jobs)
		ns.WorstStatus = models.WorstStatus(jobs)
	}
	return nodes, nil
}

// ListOfflineNodes returns nodes that last checked in more than 15 minutes ago
// and have checked in at least once (first_seen_at IS NOT NULL).
func (d *DB) ListOfflineNodes() ([]*models.Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.uid, n.name, n.client_group_id, cg.name,
		       n.psk_encrypted, n.first_seen_at, n.last_seen_at, n.created_at
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
		if err := rows.Scan(
			&n.ID, &n.UID, &n.Name, &n.ClientGroupID, &n.ClientGroup,
			&n.PSKEncrypted, &n.FirstSeenAt, &n.LastSeenAt, &n.CreatedAt,
		); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// ─── Job snapshots ───────────────────────────────────────────────────────────

func (d *DB) ListJobSnapshots(nodeID uint64) ([]models.JobSnapshot, error) {
	rows, err := d.db.Query(`
		SELECT id, node_id, job_id, job_name, program, enabled,
		       last_status, last_run_at, last_run_duration_seconds,
		       last_error, next_run_at, schedule_description, updated_at
		FROM job_snapshots WHERE node_id = ? ORDER BY job_id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []models.JobSnapshot
	for rows.Next() {
		j := models.JobSnapshot{}
		if err := rows.Scan(
			&j.ID, &j.NodeID, &j.JobID, &j.JobName, &j.Program, &j.Enabled,
			&j.LastStatus, &j.LastRunAt, &j.LastRunDurationSeconds,
			&j.LastError, &j.NextRunAt, &j.ScheduleDescription, &j.UpdatedAt,
		); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (d *DB) UpsertJobSnapshot(nodeID uint64, job models.JobStatus) error {
	_, err := d.db.Exec(`
		INSERT INTO job_snapshots
		  (node_id, job_id, job_name, program, enabled, last_status,
		   last_run_at, last_run_duration_seconds, last_error, next_run_at, schedule_description)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		  updated_at                = CURRENT_TIMESTAMP`,
		nodeID, job.ID, job.Name, job.Program, job.Enabled, job.LastStatus,
		job.LastRunAt, job.LastRunDurationSeconds, job.LastError, job.NextRunAt, job.ScheduleDescription,
	)
	return err
}

// ─── Node reports ────────────────────────────────────────────────────────────

func (d *DB) InsertNodeReport(nodeID uint64, reportedAt time.Time, payloadJSON string) error {
	_, err := d.db.Exec(
		"INSERT INTO node_reports (node_id, reported_at, payload_json) VALUES (?, ?, ?)",
		nodeID, reportedAt, payloadJSON,
	)
	return err
}

func (d *DB) ListNodeReports(nodeID uint64, limit, offset int) ([]*models.NodeReport, error) {
	rows, err := d.db.Query(`
		SELECT id, node_id, reported_at, received_at, payload_json
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
		if err := rows.Scan(&r.ID, &r.NodeID, &r.ReportedAt, &r.ReceivedAt, &r.PayloadJSON); err != nil {
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

// ─── Dashboard stats ─────────────────────────────────────────────────────────

func (d *DB) GetDashboardStats(groupIDs []uint64) (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}

	where, args := groupFilter("n.client_group_id", groupIDs)

	// Total nodes
	row := d.db.QueryRow("SELECT COUNT(*) FROM nodes n"+where, args...)
	if err := row.Scan(&stats.TotalNodes); err != nil {
		return nil, fmt.Errorf("total nodes: %w", err)
	}

	// Online nodes
	onlineArgs := append(args, interface{}(nil))
	copy(onlineArgs, args)
	onlineArgs = append([]interface{}{}, args...)
	onlineWhere := where
	if onlineWhere != "" {
		onlineWhere += " AND n.last_seen_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
	} else {
		onlineWhere = " WHERE n.last_seen_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
	}
	row = d.db.QueryRow("SELECT COUNT(*) FROM nodes n"+onlineWhere, onlineArgs...)
	if err := row.Scan(&stats.OnlineNodes); err != nil {
		return nil, fmt.Errorf("online nodes: %w", err)
	}

	// Never seen
	neverWhere := where
	if neverWhere != "" {
		neverWhere += " AND n.first_seen_at IS NULL"
	} else {
		neverWhere = " WHERE n.first_seen_at IS NULL"
	}
	row = d.db.QueryRow("SELECT COUNT(*) FROM nodes n"+neverWhere, args...)
	if err := row.Scan(&stats.NeverSeenNodes); err != nil {
		return nil, fmt.Errorf("never seen nodes: %w", err)
	}

	// Nodes with failures (any job_snapshot with last_status = 'failure')
	failQuery := `SELECT COUNT(DISTINCT js.node_id) FROM job_snapshots js
		JOIN nodes n ON n.id = js.node_id` + where + func() string {
		if where != "" {
			return " AND js.last_status = 'failure'"
		}
		return " WHERE js.last_status = 'failure'"
	}()
	row = d.db.QueryRow(failQuery, args...)
	if err := row.Scan(&stats.FailingNodes); err != nil {
		return nil, fmt.Errorf("failing nodes: %w", err)
	}

	return stats, nil
}

func (d *DB) ListGroupsWithStats(groupIDs []uint64) ([]*models.GroupWithStats, error) {
	var groups []*models.ClientGroup
	var err error
	if groupIDs == nil {
		groups, err = d.ListClientGroups()
	} else {
		// fetch specific groups with node counts
		groups = make([]*models.ClientGroup, 0)
		for _, id := range groupIDs {
			g, err2 := d.GetClientGroupByID(id)
			if err2 != nil || g == nil {
				continue
			}
			count, _ := d.CountNodesInGroup(g.ID)
			g.NodeCount = count
			groups = append(groups, g)
		}
	}
	if err != nil {
		return nil, err
	}

	result := make([]*models.GroupWithStats, 0, len(groups))
	for _, g := range groups {
		gws := &models.GroupWithStats{ClientGroup: *g}
		// get worst status across all jobs in this group
		row := d.db.QueryRow(`
			SELECT COALESCE(
			  CASE WHEN SUM(js.last_status = 'failure') > 0 THEN 'failure'
			       WHEN SUM(js.last_status = 'success') > 0 THEN 'success'
			       ELSE 'never_run' END, '')
			FROM job_snapshots js
			JOIN nodes n ON n.id = js.node_id
			WHERE n.client_group_id = ?`, g.ID)
		row.Scan(&gws.WorstStatus) //nolint:errcheck
		result = append(result, gws)
	}
	return result, nil
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
