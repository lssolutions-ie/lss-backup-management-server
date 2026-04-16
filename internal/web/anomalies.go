package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type anomaliesPageData struct {
	PageData
	Node      *models.Node
	Anomalies []*models.JobAnomaly
}

type globalAnomaliesPageData struct {
	PageData
	Anomalies     []*db.EnrichedAnomaly
	Filter        string // "all" | "ack" | "unack"
	Archive       bool   // true on /anomalies/archive
	RetentionDays uint32 // server tuning value, for the banner label
}

// HandleAnomalies renders the global Security page across all nodes.
// GET /anomalies?filter=all|ack|unack          → live view (ack'd older than N days hidden)
// GET /anomalies/archive?filter=all|ack|unack  → full history
func (s *Server) HandleAnomalies(w http.ResponseWriter, r *http.Request) {
	archive := strings.HasPrefix(r.URL.Path, "/anomalies/archive")
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "all"
	}
	tuning, _ := s.DB.GetServerTuning()
	var retention uint32
	if tuning != nil {
		retention = tuning.AnomalyAckRetentionDays
	}
	limit := 500
	if archive {
		limit = 5000
	}
	list, err := s.DB.ListEnrichedAnomalies(filter, retention, archive, limit)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	s.render(w, r, http.StatusOK, "anomalies_global.html", globalAnomaliesPageData{
		PageData:      s.newPageData(r),
		Anomalies:     list,
		Filter:        filter,
		Archive:       archive,
		RetentionDays: retention,
	})
}

// HandleNodeAnomalies renders the Security tab for a node.
// GET /nodes/{id}/anomalies
func (s *Server) HandleNodeAnomalies(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeView(w, r, node.ID) {
		return
	}
	list, err := s.DB.ListJobAnomalies(node.ID, "", false, 200)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	s.render(w, r, http.StatusOK, "anomalies.html", anomaliesPageData{
		PageData:  s.newPageData(r),
		Node:      node,
		Anomalies: list,
	})
}

// HandleNodeAnomalyCounts returns {counts: {jobID: n}} of unacked anomalies per job for a node.
// GET /nodes/{id}/anomaly-counts
func (s *Server) HandleNodeAnomalyCounts(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeView(w, r, node.ID) {
		return
	}
	counts, err := s.DB.CountUnackedAnomaliesByJob(node.ID)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "DB error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"counts": counts})
}

// HandleAnomalyBulkAck POST /anomalies/bulk-ack  body: ids=1,2,3&action=ack|unack
func (s *Server) HandleAnomalyBulkAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)
	action := r.FormValue("action")
	raw := r.FormValue("ids")
	if raw == "" || (action != "ack" && action != "unack") {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	muteHours, _ := strconv.Atoi(r.FormValue("mute_hours")) // 0 or absent = no mute
	var done, muted int
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			continue
		}
		if action == "ack" {
			if err := s.DB.AcknowledgeAnomaly(id, user.ID, note); err == nil {
				done++
				if muteHours > 0 {
					if nodeID, jobID, err := s.DB.GetAnomalyTarget(id); err == nil {
						until := time.Now().Add(time.Duration(muteHours) * time.Hour)
						if err := s.DB.SetJobSilence(nodeID, jobID, &until,
							"muted via anomaly ack: "+note, user.ID); err == nil {
							muted++
						}
					}
				}
			}
		} else {
			if err := s.DB.UnacknowledgeAnomaly(id); err == nil {
				done++
			}
		}
	}
	if done > 0 {
		verb := "ack"
		category := "anomaly_acknowledged"
		severity := "info"
		if action == "unack" {
			verb = "unack"
			category = "anomaly_unacknowledged"
			severity = "warn"
		}
		details := map[string]string{"count": strconv.Itoa(done), "ids": raw}
		if note != "" {
			details["note"] = note
		}
		if muted > 0 {
			details["muted"] = strconv.Itoa(muted)
			details["mute_hours"] = strconv.Itoa(muteHours)
		}
		s.auditServer(r, category, severity, "bulk_"+verb, "anomaly", raw,
			"Bulk "+verb+" of "+strconv.Itoa(done)+" anomalies", details)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"updated":` + strconv.Itoa(done) + `}`))
}

// HandleAnomalyDiff POST /anomalies/{id}/diff — SSHes to the node and runs
// lss-backup-cli repo-diff to show exactly which files changed between the
// two snapshots that triggered this anomaly. Requires SSH creds (cached or
// provided in the request body).
func (s *Server) HandleAnomalyDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/anomalies/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "diff" {
		http.NotFound(w, r)
		return
	}
	anomalyID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	nodeID, jobID, anomErr := s.DB.GetAnomalyTarget(anomalyID)
	if anomErr != nil {
		jsonError(w, "anomaly not found", http.StatusNotFound)
		return
	}

	// Get prev/curr snapshot IDs from the anomaly row.
	anomalies, _ := s.DB.ListJobAnomalies(nodeID, jobID, false, 500)
	var prevSnap, currSnap string
	for _, a := range anomalies {
		if a.ID == anomalyID {
			prevSnap = a.PrevSnapshotID
			currSnap = a.CurrSnapshotID
			break
		}
	}
	if prevSnap == "" || currSnap == "" {
		jsonError(w, "anomaly has no snapshot pair for diff", http.StatusUnprocessableEntity)
		return
	}

	node, err := s.DB.GetNodeByID(nodeID)
	if err != nil || node == nil {
		jsonError(w, "node not found", http.StatusNotFound)
		return
	}
	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel — cannot run diff", http.StatusBadGateway)
		return
	}

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		jsonError(w, "ssh_creds_required", http.StatusUnauthorized)
		return
	}

	cmd := fmt.Sprintf("%s repo-diff --json %s %s %s",
		cliPath(node.HwOS), jobID, prevSnap, currSnap)
	output, err := sshExecOnNodeSudo(node, username, password, cmd)
	if err != nil {
		logx.FromContext(r.Context()).Error("repo-diff failed",
			"node_id", node.ID, "job_id", jobID, "err", err.Error())
		jsonError(w, "diff failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleResetAuditChain POST /nodes/{id}/reset-audit-chain (superadmin only)
func (s *Server) HandleResetAuditChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if err := s.DB.ResetNodeAuditChain(node.ID); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "DB error")
		return
	}
	s.auditServer(r, "audit_chain_reset", "critical", "reset", "node",
		strconv.FormatUint(node.ID, 10),
		"Audit chain reset for node "+node.Name,
		map[string]string{"node_id": strconv.FormatUint(node.ID, 10), "node_name": node.Name})
	setFlash(w, "Audit chain reset for "+node.Name+". Next events from this node will start a fresh chain.")
	http.Redirect(w, r, "/nodes/"+strconv.FormatUint(node.ID, 10), http.StatusSeeOther)
}

// HandleAnomalyAck POST /anomalies/{id}/ack | /anomalies/{id}/unack
func (s *Server) HandleAnomalyAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)

	rest := strings.TrimPrefix(r.URL.Path, "/anomalies/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	muteHours, _ := strconv.Atoi(r.FormValue("mute_hours"))
	switch parts[1] {
	case "ack":
		if err := s.DB.AcknowledgeAnomaly(id, user.ID, note); err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "DB error")
			return
		}
		details := map[string]string{}
		if note != "" {
			details["note"] = note
		}
		if muteHours > 0 {
			if nodeID, jobID, err := s.DB.GetAnomalyTarget(id); err == nil {
				until := time.Now().Add(time.Duration(muteHours) * time.Hour)
				if err := s.DB.SetJobSilence(nodeID, jobID, &until,
					"muted via anomaly ack: "+note, user.ID); err == nil {
					details["muted_until"] = until.Format(time.RFC3339)
					details["mute_hours"] = strconv.Itoa(muteHours)
				}
			}
		}
		s.auditServer(r, "anomaly_acknowledged", "info", "ack", "anomaly", strconv.FormatUint(id, 10),
			"Acknowledged anomaly", details)
	case "unack":
		if err := s.DB.UnacknowledgeAnomaly(id); err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "DB error")
			return
		}
		s.auditServer(r, "anomaly_unacknowledged", "warn", "unack", "anomaly", strconv.FormatUint(id, 10), "Unacknowledged anomaly", nil)
	default:
		http.NotFound(w, r)
		return
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
