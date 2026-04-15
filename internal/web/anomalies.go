package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
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
		log.Printf("anomalies global: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		log.Printf("anomalies: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		http.Error(w, "DB error", http.StatusInternalServerError)
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
	var done int
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			continue
		}
		if action == "ack" {
			if err := s.DB.AcknowledgeAnomaly(id, user.ID); err == nil {
				done++
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
		s.auditServer(r, category, severity, "bulk_"+verb, "anomaly", raw,
			"Bulk "+verb+" of "+strconv.Itoa(done)+" anomalies",
			map[string]string{"count": strconv.Itoa(done), "ids": raw})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"updated":` + strconv.Itoa(done) + `}`))
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
	switch parts[1] {
	case "ack":
		if err := s.DB.AcknowledgeAnomaly(id, user.ID); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		s.auditServer(r, "anomaly_acknowledged", "info", "ack", "anomaly", strconv.FormatUint(id, 10), "Acknowledged anomaly", nil)
	case "unack":
		if err := s.DB.UnacknowledgeAnomaly(id); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
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
