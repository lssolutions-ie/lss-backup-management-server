package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// InsertServerAuditLog records a user-originated action on the management server.
// userID may be 0 if unauthenticated (login failures etc.).
func (d *DB) InsertServerAuditLog(userID uint64, username, ip, category, severity, action, entityType, entityID, message string, details map[string]string) error {
	var detailsJSON sql.NullString
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err == nil {
			if len(b) > 8192 {
				b = b[:8192]
			}
			detailsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	var uid sql.NullInt64
	if userID > 0 {
		uid = sql.NullInt64{Int64: int64(userID), Valid: true}
	}
	_, err := d.db.Exec(`
		INSERT INTO audit_log
		  (ts, source, user_id, username, ip, category, severity, actor, action, entity_type, entity_id, message, details_json)
		VALUES (NOW(), 'server', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uid, username, ip, category, severity, "user:"+username, action, entityType, entityID, truncate(message, 500), detailsJSON)
	return err
}

// InsertNodeAuditEvents inserts a batch of events shipped from a CLI node.
// Returns the highest contiguous seq that was successfully inserted — used for the heartbeat ack.
// Events may arrive with gaps; we insert in-order and stop at the first gap.
// Caller must pass events sorted by seq ascending.
func (d *DB) InsertNodeAuditEvents(nodeID uint64, prevAck uint64, events []models.AuditEvent) (uint64, error) {
	if len(events) == 0 {
		return prevAck, nil
	}
	ackedSeq := prevAck
	for _, e := range events {
		// Enforce strict-in-order ack: we only advance the ack pointer if seq == ackedSeq+1.
		if e.Seq != ackedSeq+1 {
			// Store the event anyway (idempotent via UNIQUE (source_node_id, source_seq)),
			// but stop advancing the ack so the CLI resends the missing one next heartbeat.
			if err := d.insertNodeAudit(nodeID, e); err != nil {
				return ackedSeq, err
			}
			continue
		}
		if err := d.insertNodeAudit(nodeID, e); err != nil {
			return ackedSeq, err
		}
		ackedSeq = e.Seq
	}
	if ackedSeq > prevAck {
		if _, err := d.db.Exec("UPDATE nodes SET audit_ack_seq = ? WHERE id = ?", ackedSeq, nodeID); err != nil {
			return ackedSeq, err
		}
	}
	return ackedSeq, nil
}

func (d *DB) insertNodeAudit(nodeID uint64, e models.AuditEvent) error {
	var detailsJSON sql.NullString
	if len(e.Details) > 0 {
		b, err := json.Marshal(e.Details)
		if err == nil {
			if len(b) > 8192 {
				b = b[:8192]
			}
			detailsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	sev := e.Severity
	if sev != "warn" && sev != "critical" {
		sev = "info"
	}
	ts := time.Unix(e.TS, 0)
	_, err := d.db.Exec(`
		INSERT IGNORE INTO audit_log
		  (ts, source, source_node_id, source_seq, category, severity, actor, message, details_json)
		VALUES (?, 'node', ?, ?, ?, ?, ?, ?, ?)`,
		ts, nodeID, e.Seq, e.Category, sev, e.Actor, truncate(e.Message, 500), detailsJSON)
	return err
}

// GetNodeAuditAckSeq returns the highest seq already acked for this node (0 if none).
func (d *DB) GetNodeAuditAckSeq(nodeID uint64) (uint64, error) {
	var n uint64
	err := d.db.QueryRow("SELECT audit_ack_seq FROM nodes WHERE id = ?", nodeID).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// EnrichedAuditLog is an audit row decorated with node/client display names.
type EnrichedAuditLog struct {
	*models.AuditLog
	NodeName   string
	NodeUID    string
	ClientID   uint64
	ClientName string
}

// ListAuditLog returns recent audit rows. If nodeID > 0, scoped to that node.
// source: "" (all) | "server" | "node".
func (d *DB) ListAuditLog(nodeID uint64, source string, limit int) ([]*EnrichedAuditLog, error) {
	if limit <= 0 {
		limit = 500
	}
	var conds []string
	var args []interface{}
	if nodeID > 0 {
		conds = append(conds, "a.source_node_id = ?")
		args = append(args, nodeID)
	}
	if source == "server" || source == "node" {
		conds = append(conds, "a.source = ?")
		args = append(args, source)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	q := fmt.Sprintf(`
		SELECT a.id, a.ts, a.source, a.source_node_id, a.source_seq,
		       a.user_id, a.username, a.ip,
		       a.category, a.severity, a.actor, a.action, a.entity_type, a.entity_id, a.message,
		       COALESCE(a.details_json, ''),
		       COALESCE(n.name, ''), COALESCE(n.uid, ''), COALESCE(n.client_group_id, 0), COALESCE(c.name, '')
		FROM audit_log a
		LEFT JOIN nodes n         ON n.id = a.source_node_id
		LEFT JOIN client_groups c ON c.id = n.client_group_id
		%s
		ORDER BY a.ts DESC, a.id DESC
		LIMIT ?`, where)
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EnrichedAuditLog
	for rows.Next() {
		ea := &EnrichedAuditLog{AuditLog: &models.AuditLog{}}
		var nid, useq sql.NullInt64
		var uid sql.NullInt64
		if err := rows.Scan(&ea.ID, &ea.TS, &ea.Source, &nid, &useq,
			&uid, &ea.Username, &ea.IP,
			&ea.Category, &ea.Severity, &ea.Actor, &ea.Action, &ea.EntityType, &ea.EntityID, &ea.Message,
			&ea.DetailsJSON,
			&ea.NodeName, &ea.NodeUID, &ea.ClientID, &ea.ClientName); err != nil {
			return nil, err
		}
		if nid.Valid {
			v := uint64(nid.Int64)
			ea.SourceNodeID = &v
		}
		if useq.Valid {
			v := uint64(useq.Int64)
			ea.SourceSeq = &v
		}
		if uid.Valid {
			v := uint64(uid.Int64)
			ea.UserID = &v
		}
		out = append(out, ea)
	}
	return out, rows.Err()
}

// PruneAuditLog deletes rows older than N days. Safe no-op if days == 0 (forever).
func (d *DB) PruneAuditLog(days uint32) (int64, error) {
	if days == 0 {
		return 0, nil
	}
	res, err := d.db.Exec(fmt.Sprintf("DELETE FROM audit_log WHERE ts < NOW() - INTERVAL %d DAY", days))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
