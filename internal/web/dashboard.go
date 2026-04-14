package web

import (
	"log"
	"net/http"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type dashboardPageData struct {
	PageData
	Stats   *models.DashboardStats
	Groups  []*models.GroupWithStats
	Nodes   []*models.NodeWithStatus
	AllTags []*models.Tag
}

func (s *Server) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := r.Context().Value(ctxUser).(*models.User)
	pd := s.newPageData(r)

	var groupIDs []uint64
	var visibleNodeIDs map[uint64]models.AccessLevel
	if !user.IsSuperAdmin() {
		ids, err := s.DB.GetUserClientGroupIDs(user.ID)
		if err != nil {
			log.Printf("dashboard: get group ids: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		groupIDs = ids
		visibleNodeIDs, err = s.DB.ListVisibleNodeIDsForUser(user.ID)
		if err != nil {
			log.Printf("dashboard: visible nodes: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	stats, err := s.DB.GetDashboardStats(groupIDs)
	if err != nil {
		log.Printf("dashboard: get stats: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	groups, err := s.DB.ListGroupsWithStats(groupIDs)
	if err != nil {
		log.Printf("dashboard: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	nodes, err := s.DB.ListNodesWithStatus(groupIDs)
	if err != nil {
		log.Printf("dashboard: list nodes: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// For non-superadmin, filter nodes to only those visible via tag-permissions.
	if visibleNodeIDs != nil {
		filtered := nodes[:0]
		for _, n := range nodes {
			if _, ok := visibleNodeIDs[n.ID]; ok {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}

	// Load tags for all nodes in one query.
	allNodeTags, _ := s.DB.GetAllNodeTags()
	for _, n := range nodes {
		n.Tags = allNodeTags[n.ID]
	}
	allTags, _ := s.DB.ListTags()

	s.render(w, r, http.StatusOK, "dashboard.html", dashboardPageData{
		PageData: pd,
		Stats:    stats,
		Groups:   groups,
		Nodes:    nodes,
		AllTags:  allTags,
	})
}
