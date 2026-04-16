package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

var auditDBLg = logx.Component("db.audit")

// gapStalenessThreshold is how old a gap must be before the ingest path skips
// past it. A gap that's never been filled in this long is assumed permanently
// lost (e.g. CLI-side migration trimmed an event the server never received).
const gapStalenessThreshold = 1 * time.Hour

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

// InsertNodeAuditEvents inserts a batch of events shipped from a CLI node and
// returns the highest contiguous seq currently stored for this node — used for
// the heartbeat ack.
//
// Events may arrive with gaps; we insert each one (idempotent via
// UNIQUE(source_node_id, source_seq)). After the batch lands we reconcile the
// ack pointer from actual DB state, walking seqs starting at prevAck+1 and
// advancing through the contiguous run. This handles three cases correctly:
//   1. Normal in-order delivery: ack advances with every event.
//   2. CLI-side migration that backfilled rows: events already in DB still
//      count toward the contiguous run.
//   3. Real gaps: ack stops at the missing seq; CLI resends next heartbeat.
//
// Caller must pass events sorted by seq ascending.
func (d *DB) InsertNodeAuditEvents(nodeID uint64, prevAck uint64, events []models.AuditEvent) (uint64, error) {
	for _, e := range events {
		if err := d.insertNodeAudit(nodeID, e); err != nil {
			return prevAck, err
		}
	}
	newAck, err := d.computeContiguousAck(nodeID, prevAck)
	if err != nil {
		return prevAck, err
	}

	// If reconcile didn't move the pointer but events ARE present past prevAck,
	// there's a gap. CLI-side queue/migration bugs can permanently drop a seq;
	// skip past gaps that have been there longer than gapStalenessThreshold so
	// the ack doesn't freeze forever.
	if newAck == prevAck {
		var nextSeq sql.NullInt64
		var nextDetected sql.NullTime
		err := d.db.QueryRow(
			"SELECT MIN(source_seq), MIN(detected_at) FROM audit_log WHERE source_node_id=? AND source_seq > ?",
			nodeID, prevAck).Scan(&nextSeq, &nextDetected)
		if err == nil && nextSeq.Valid && nextDetected.Valid {
			missingFrom := prevAck + 1
			missingTo := uint64(nextSeq.Int64) - 1
			if missingFrom <= missingTo && time.Since(nextDetected.Time) > gapStalenessThreshold {
				skipTo := uint64(nextSeq.Int64) - 1
				auditDBLg.Warn("audit ack stuck; skipping stale gap",
					"node_id", nodeID,
					"missing_from", missingFrom,
					"missing_to", missingTo,
					"gap_age", time.Since(nextDetected.Time).String())
				newAck = skipTo
				newAck, err = d.computeContiguousAck(nodeID, newAck)
				if err != nil {
					return prevAck, err
				}
			}
		}
	}

	if newAck > prevAck {
		if _, err := d.db.Exec("UPDATE nodes SET audit_ack_seq = ? WHERE id = ?", newAck, nodeID); err != nil {
			return prevAck, err
		}
	}
	return newAck, nil
}

// computeContiguousAck returns the highest seq M such that every seq in
// (prevAck, M] is present for the given node. Walks at most a few thousand
// rows per call — bounded by typical heartbeat batch sizes.
func (d *DB) computeContiguousAck(nodeID uint64, prevAck uint64) (uint64, error) {
	rows, err := d.db.Query(
		"SELECT source_seq FROM audit_log WHERE source_node_id=? AND source_seq > ? ORDER BY source_seq ASC LIMIT 5000",
		nodeID, prevAck)
	if err != nil {
		return prevAck, err
	}
	defer rows.Close()
	ack := prevAck
	for rows.Next() {
		var s uint64
		if err := rows.Scan(&s); err != nil {
			return ack, err
		}
		if s != ack+1 {
			break
		}
		ack = s
	}
	return ack, rows.Err()
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

// GetNodeAuditChainHead returns the last verified HMAC for this node (empty if none).
func (d *DB) GetNodeAuditChainHead(nodeID uint64) (string, error) {
	var head string
	err := d.db.QueryRow("SELECT audit_chain_head FROM nodes WHERE id = ?", nodeID).Scan(&head)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return head, err
}

// SetNodeAuditChainHead persists the chain head after successful verification.
func (d *DB) SetNodeAuditChainHead(nodeID uint64, head string) error {
	_, err := d.db.Exec("UPDATE nodes SET audit_chain_head = ? WHERE id = ?", head, nodeID)
	return err
}

// ResetNodeAuditChain clears the chain head and optionally the ack seq (for PSK rotation / manual reset).
func (d *DB) ResetNodeAuditChain(nodeID uint64) error {
	_, err := d.db.Exec("UPDATE nodes SET audit_chain_head = '', audit_ack_seq = 0 WHERE id = ?", nodeID)
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
	if source == "server" || source == "node" || source == "host" {
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

// InsertNodeAuditIgnoreErr inserts a single node event, ignoring errors.
// Used when the HMAC chain is broken — we still want the data for forensics
// but don't advance the ack pointer.
func (d *DB) InsertNodeAuditIgnoreErr(nodeID uint64, e models.AuditEvent) {
	_ = d.insertNodeAudit(nodeID, e)
}

// GetHostAuditCursor returns the journal cursor we last successfully consumed
// host-audit events past. Empty string on first run = "start from now".
func (d *DB) GetHostAuditCursor() (string, error) {
	var cur string
	err := d.db.QueryRow("SELECT journal_cursor FROM host_audit_state WHERE id = 1").Scan(&cur)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return cur, err
}

// SetHostAuditCursor persists the cursor so the next tick resumes after it.
func (d *DB) SetHostAuditCursor(cursor string) error {
	_, err := d.db.Exec(
		"INSERT INTO host_audit_state (id, journal_cursor) VALUES (1, ?) ON DUPLICATE KEY UPDATE journal_cursor = VALUES(journal_cursor)",
		cursor)
	return err
}

// InsertHostAuditEvent records one event observed from the local systemd
// journal. Best-effort dedup is the caller's responsibility (use the journal
// cursor to avoid re-emitting old events).
func (d *DB) InsertHostAuditEvent(category, severity, actor, message string, details map[string]string) error {
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
	_, err := d.db.Exec(`
		INSERT INTO audit_log
		  (ts, source, category, severity, actor, message, details_json)
		VALUES (NOW(), 'host', ?, ?, ?, ?, ?)`,
		category, severity, actor, truncate(message, 500), detailsJSON)
	return err
}

// FireSilentNodeAlerts inserts one audit_log row per node whose last_seen_at is
// older than thresholdMinutes AND doesn't already have a 'node_silent' alert
// since that last_seen_at. Atomic-ish: a single INSERT … SELECT statement so
// concurrent calls converge on at most one alert per silence transition.
func (d *DB) FireSilentNodeAlerts(thresholdMinutes uint32) error {
	_, err := d.db.Exec(`
		INSERT INTO audit_log
		  (ts, source, source_node_id, category, severity, actor, action, entity_type, entity_id, message)
		SELECT NOW(), 'server', n.id, 'node_silent', 'warn', 'system', 'detect', 'node',
		       CAST(n.id AS CHAR),
		       CONCAT('Node "', n.name, '" missed heartbeat — last seen ', DATE_FORMAT(n.last_seen_at, '%Y-%m-%d %H:%i:%s'))
		FROM nodes n
		WHERE n.last_seen_at IS NOT NULL
		  AND n.last_seen_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)
		  AND NOT EXISTS (
		    SELECT 1 FROM audit_log a
		    WHERE a.source_node_id = n.id
		      AND a.category = 'node_silent'
		      AND a.ts > n.last_seen_at
		  )`, thresholdMinutes)
	return err
}

// PruneAuditLog deletes rows older than N days. Safe no-op if days == 0 (forever).
func (d *DB) PruneAuditLog(days uint32) (int64, error) {
	if days == 0 {
		return 0, nil
	}
	res, err := d.db.Exec("DELETE FROM audit_log WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
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
