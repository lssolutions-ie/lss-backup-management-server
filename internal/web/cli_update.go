package web

import (
	"fmt"
	"net/http"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// HandleScheduleCLIUpdate marks a node for CLI self-update on next heartbeat.
// POST /nodes/{id}/update-cli
func (s *Server) HandleScheduleCLIUpdate(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := s.DB.SetNodeCLIUpdatePending(node.ID, true); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	// Audit log
	user := r.Context().Value(ctxUser).(*models.User)
	_ = s.DB.InsertServerAuditLog(
		user.ID, user.Username, r.RemoteAddr,
		"cli_update_scheduled", "info",
		"schedule", "node", fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("CLI update scheduled for node %s", node.Name),
		nil,
	)

	// Redirect back to referrer or dashboard
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
