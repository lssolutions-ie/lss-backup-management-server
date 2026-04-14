package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type anomaliesPageData struct {
	PageData
	Node      *models.Node
	Anomalies []*models.JobAnomaly
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

// HandleAnomalyAck POST /anomalies/{id}/ack
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
	idStr := strings.TrimPrefix(r.URL.Path, "/anomalies/")
	idStr = strings.TrimSuffix(idStr, "/ack")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.AcknowledgeAnomaly(id, user.ID); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
