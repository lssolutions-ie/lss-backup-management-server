package web

import (
	"net/http"
	"strconv"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

type pendingNode struct {
	ID        uint64
	UID       string
	Client    string
	CreatedAt string
	TokenUsed bool
	Expired   bool
}

type pendingNodesPageData struct {
	PageData
	Nodes []pendingNode
}

// HandlePendingNodes shows nodes created via server-assisted install that
// haven't completed registration (no first heartbeat yet).
func (s *Server) HandlePendingNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.RawQuery(`
		SELECT n.id, n.uid, COALESCE(cg.name, ''), n.created_at,
		       (SELECT COUNT(*) FROM node_install_tokens t WHERE t.node_id = n.id AND t.used_at IS NOT NULL) AS token_used,
		       (SELECT COUNT(*) FROM node_install_tokens t WHERE t.node_id = n.id AND t.expires_at < NOW() AND t.used_at IS NULL) AS token_expired
		FROM nodes n
		LEFT JOIN client_groups cg ON cg.id = n.client_group_id
		WHERE n.first_seen_at IS NULL
		ORDER BY n.created_at DESC`)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	defer rows.Close()

	var nodes []pendingNode
	for rows.Next() {
		var pn pendingNode
		var created string
		var used, expired int
		if err := rows.Scan(&pn.ID, &pn.UID, &pn.Client, &created, &used, &expired); err != nil {
			continue
		}
		pn.CreatedAt = created
		pn.TokenUsed = used > 0
		pn.Expired = expired > 0
		nodes = append(nodes, pn)
	}

	s.render(w, r, http.StatusOK, "pending_nodes.html", pendingNodesPageData{
		PageData: s.newPageData(r),
		Nodes:    nodes,
	})
}

// HandleDeletePendingNode removes a pending node that never completed registration.
func (s *Server) HandleDeletePendingNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	idStr := r.FormValue("node_id")
	nodeID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Only delete if it's actually pending (no first_seen_at).
	var count int
	row, _ := s.DB.RawQuery("SELECT COUNT(*) FROM nodes WHERE id = ? AND first_seen_at IS NULL", nodeID)
	if row.Next() {
		row.Scan(&count)
	}
	row.Close()

	if count == 0 {
		setFlash(w, "Node is not pending or does not exist.")
		http.Redirect(w, r, "/settings/pending-nodes", http.StatusSeeOther)
		return
	}

	if err := s.DB.DeleteNode(nodeID); err != nil {
		logx.FromContext(r.Context()).Error("delete pending node failed", "err", err.Error())
		setFlash(w, "Could not delete node.")
	} else {
		s.auditServer(r, "pending_node_deleted", "info", "delete", "node",
			strconv.FormatUint(nodeID, 10), "Deleted pending node", nil)
		setFlash(w, "Pending node deleted.")
	}

	http.Redirect(w, r, "/settings/pending-nodes", http.StatusSeeOther)
}
