package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type nodesListPageData struct {
	PageData
	Nodes            []*models.NodeWithStatus
	AllTags          []*models.Tag
	Groups           []*models.GroupWithStats
	LatestCLIVersion string
	DRConfigured     bool
}

// HandleNodesList renders the standalone "All Nodes" page with multi-select for
// bulk CLI updates and bulk DR enable.
func (s *Server) HandleNodesList(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ctxUser).(*models.User)
	pd := s.newPageData(r)

	var groupIDs []uint64
	var visibleNodeIDs map[uint64]models.AccessLevel
	if !user.IsSuperAdmin() {
		ids, err := s.DB.GetUserClientGroupIDs(user.ID)
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
		groupIDs = ids
		visibleNodeIDs, err = s.DB.ListVisibleNodeIDsForUser(user.ID)
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
	}

	nodes, err := s.DB.ListNodesWithStatus(groupIDs)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	if visibleNodeIDs != nil {
		filtered := nodes[:0]
		for _, n := range nodes {
			if _, ok := visibleNodeIDs[n.ID]; ok {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}

	allNodeTags, _ := s.DB.GetAllNodeTags()
	for _, n := range nodes {
		n.Tags = allNodeTags[n.ID]
	}
	allTags, _ := s.DB.ListTags()

	groups, err := s.DB.ListGroupsWithStats(groupIDs)
	if err != nil {
		groups = nil
	}

	var latestCLI string
	if tuning, err := s.DB.GetServerTuning(); err == nil {
		latestCLI = tuning.LatestCLIVersion
	}

	var drConfigured bool
	if cfg, err := s.DB.GetDRConfig(s.AppKey); err == nil && cfg.S3Endpoint != "" {
		drConfigured = true
	}

	s.render(w, r, http.StatusOK, "nodes_list.html", nodesListPageData{
		PageData:         pd,
		Nodes:            nodes,
		AllTags:          allTags,
		Groups:           groups,
		LatestCLIVersion: latestCLI,
		DRConfigured:     drConfigured,
	})
}

// HandleBulkUpdateCLI marks selected nodes for CLI update on their next heartbeat.
// POST /nodes/bulk-update-cli — body: ids=1,2,3
func (s *Server) HandleBulkUpdateCLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	ids := parseIDList(r.FormValue("ids"))
	if len(ids) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "no node IDs provided"})
		return
	}

	count := 0
	for _, id := range ids {
		if err := s.DB.SetNodeCLIUpdatePending(id, true); err == nil {
			count++
		}
	}

	s.auditServer(r, "bulk_cli_update", "info", "bulk_update", "node", "",
		fmt.Sprintf("Bulk CLI update scheduled for %d nodes", count), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": count})
}

// HandleBulkEnableDR enables DR for selected nodes.
// POST /nodes/bulk-enable-dr — body: ids=1,2,3
func (s *Server) HandleBulkEnableDR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	ids := parseIDList(r.FormValue("ids"))
	if len(ids) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "no node IDs provided"})
		return
	}

	count := 0
	for _, id := range ids {
		if err := s.DB.SetNodeDREnabled(id, true); err == nil {
			count++
		}
	}

	s.auditServer(r, "bulk_dr_enabled", "warn", "bulk_enable", "node", "",
		fmt.Sprintf("Bulk DR enabled for %d nodes", count), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": count})
}

// parseIDList splits a comma-separated string of numeric IDs.
func parseIDList(s string) []uint64 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var ids []uint64
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if id, err := strconv.ParseUint(p, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}
