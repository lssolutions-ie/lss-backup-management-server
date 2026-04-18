package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/db"
	"github.com/lssolutions-ie/lss-backup-server/internal/models"
)

type dashboardPageData struct {
	PageData
	Stats            *models.DashboardStats
	Groups           []*models.GroupWithStats
	Nodes            []*models.NodeWithStatus
	AllTags          []*models.Tag
	AnomalyCount     int
	LatestCLIVersion string
	DRProtected      int
	DRTotal          int
	RecentAudit      []*db.EnrichedAuditLog
	ServerUptime     string
	LastBackupAge    string
	DBSizeHuman      string
	RecordingSize    string
	ServerNowFormatted string
	ServerTZ           string
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

	stats, err := s.DB.GetDashboardStats(groupIDs)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	groups, err := s.DB.ListGroupsWithStats(groupIDs)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	nodes, err := s.DB.ListNodesWithStatus(groupIDs)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
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
	anomalyCount, _ := s.DB.CountUnackedAnomalies()

	var latestCLI string
	if tuning, err := s.DB.GetServerTuning(); err == nil {
		latestCLI = tuning.LatestCLIVersion
	}

	// DR status summary — query directly since ListNodesWithStatus doesn't fetch DR columns
	var drProtected, drTotal int
	if r, err := s.DB.RawQuery("SELECT COUNT(*) FROM nodes WHERE first_seen_at IS NOT NULL"); err == nil {
		if r.Next() { r.Scan(&drTotal) }; r.Close()
	}
	if r, err := s.DB.RawQuery("SELECT COUNT(*) FROM nodes WHERE first_seen_at IS NOT NULL AND dr_enabled = 1 AND dr_last_status = 'success'"); err == nil {
		if r.Next() { r.Scan(&drProtected) }; r.Close()
	}

	// Recent audit activity (last 5 events)
	recentAudit, _ := s.DB.ListAuditLog(0, "", 5)

	// System health
	serverUptime := uptimeSince(ServerStartTime)
	lastBackupAge := s.getLastBackupAge()
	dbSize := s.getDBSize()
	recSize := s.getRecordingSize()

	now := time.Now()
	zone, _ := now.Zone()
	s.render(w, r, http.StatusOK, "dashboard.html", dashboardPageData{
		PageData:         pd,
		Stats:            stats,
		Groups:           groups,
		Nodes:            nodes,
		AllTags:          allTags,
		AnomalyCount:     anomalyCount,
		LatestCLIVersion: latestCLI,
		DRProtected:      drProtected,
		DRTotal:          drTotal,
		RecentAudit:      recentAudit,
		ServerUptime:     serverUptime,
		LastBackupAge:    lastBackupAge,
		DBSizeHuman:      dbSize,
		RecordingSize:    recSize,
		ServerNowFormatted: now.Format("2006-01-02T15:04:05Z"),
		ServerTZ:           zone,
	})
}

var ServerStartTime = time.Now()

func uptimeSince(start time.Time) string {
	d := time.Since(start)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

func (s *Server) getLastBackupAge() string {
	rows, err := s.DB.RawQuery("SELECT ts FROM audit_log WHERE category = 'backup_created' ORDER BY ts DESC LIMIT 1")
	if err != nil {
		return "never"
	}
	defer rows.Close()
	if !rows.Next() {
		return "never"
	}
	var ts time.Time
	if err := rows.Scan(&ts); err != nil {
		return "never"
	}
	d := time.Since(ts)
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours())/24)
}

func (s *Server) getDBSize() string {
	rows, err := s.DB.RawQuery("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) FROM information_schema.tables WHERE table_schema = DATABASE()")
	if err != nil {
		return "?"
	}
	defer rows.Close()
	if !rows.Next() {
		return "?"
	}
	var size float64
	if err := rows.Scan(&size); err != nil {
		return "?"
	}
	if size < 1 {
		return fmt.Sprintf("%.0f KB", size*1024)
	}
	return fmt.Sprintf("%.1f MB", size)
}

func (s *Server) getRecordingSize() string {
	rows, err := s.DB.RawQuery("SELECT COUNT(*) FROM audit_log WHERE category = 'terminal_opened' AND details_json LIKE '%session_file%'")
	if err != nil {
		return "0"
	}
	defer rows.Close()
	if !rows.Next() {
		return "0"
	}
	var count int
	rows.Scan(&count)
	return fmt.Sprintf("%d sessions", count)
}
