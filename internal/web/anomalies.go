package web

import (
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
	Anomalies []*db.EnrichedAnomaly
	Filter    string // "all" | "ack" | "unack"
}

// HandleAnomalies renders the global Security page across all nodes.
// GET /anomalies?filter=all|ack|unack
func (s *Server) HandleAnomalies(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "all"
	}
	list, err := s.DB.ListEnrichedAnomalies(filter, 500)
	if err != nil {
		log.Printf("anomalies global: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "anomalies_global.html", globalAnomaliesPageData{
		PageData:  s.newPageData(r),
		Anomalies: list,
		Filter:    filter,
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
	case "unack":
		if err := s.DB.UnacknowledgeAnomaly(id); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
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
