package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/worker"
)

type updateSettingsPageData struct {
	PageData
	LatestCLIVersion             string
	LatestCLIVersionCheckedAt    *time.Time
	ServerVersion                string
	LatestServerVersion          string
	LatestServerVersionCheckedAt *time.Time
	UpdateCheckInterval          uint32
}

// HandleUpdateSettings renders the Software Updates status page. Superadmin only.
func (s *Server) HandleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	t, err := s.DB.GetServerTuning()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	s.render(w, r, http.StatusOK, "update_settings.html", updateSettingsPageData{
		PageData:                     s.newPageData(r),
		LatestCLIVersion:             t.LatestCLIVersion,
		LatestCLIVersionCheckedAt:    t.LatestCLIVersionCheckedAt,
		ServerVersion:                ServerVersion,
		LatestServerVersion:          t.LatestServerVersion,
		LatestServerVersionCheckedAt: t.LatestServerVersionCheckedAt,
		UpdateCheckInterval:          t.UpdateCheckIntervalMinutes,
	})
}

// HandleCheckCLIVersion triggers an immediate CLI version check. POST only, superadmin.
func (s *Server) HandleCheckCLIVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	vc := worker.NewVersionChecker(s.DB)
	version, err := vc.CheckCLIVersion()
	if err != nil {
		setFlash(w, "CLI version check failed: "+err.Error())
	} else if version == "" {
		setFlash(w, "CLI version check complete. No tags found.")
	} else {
		setFlash(w, fmt.Sprintf("CLI version check complete. Latest: %s", version))
	}

	s.auditServer(r, "version_check", "info", "check", "cli_version", "", "Manual CLI version check", nil)

	http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
}

// HandleCheckServerVersion triggers an immediate server version check. POST only, superadmin.
func (s *Server) HandleCheckServerVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	vc := worker.NewVersionChecker(s.DB)
	version, err := vc.CheckServerVersion()
	if err != nil {
		setFlash(w, "Server version check failed: "+err.Error())
	} else if version == "" {
		setFlash(w, "Server version check complete. No tags found.")
	} else {
		setFlash(w, fmt.Sprintf("Server version check complete. Latest: %s", version))
	}

	s.auditServer(r, "version_check", "info", "check", "server_version", "", "Manual server version check", nil)

	http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
}
