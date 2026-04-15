package web

import (
	"log"
	"net/http"
	"strconv"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
)

type auditPageData struct {
	PageData
	Entries  []*db.EnrichedAuditLog
	Source   string // "" | "server" | "node"
	NodeID   uint64
	NodeName string
}

// HandleAudit renders /audit — global cross-source audit log. Superadmin + manager only.
func (s *Server) HandleAudit(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("source")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 1000
	}
	list, err := s.DB.ListAuditLog(0, src, limit)
	if err != nil {
		log.Printf("audit: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "audit.html", auditPageData{
		PageData: s.newPageData(r),
		Entries:  list,
		Source:   src,
	})
}

// HandleNodeAudit renders /nodes/{id}/audit — per-node audit tab.
func (s *Server) HandleNodeAudit(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeView(w, r, node.ID) {
		return
	}
	list, err := s.DB.ListAuditLog(node.ID, "", 1000)
	if err != nil {
		log.Printf("node audit: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "audit.html", auditPageData{
		PageData: s.newPageData(r),
		Entries:  list,
		NodeID:   node.ID,
		NodeName: node.Name,
	})
}
