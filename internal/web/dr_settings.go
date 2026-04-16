package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type drSettingsPageData struct {
	PageData
	Config  *models.DRConfig
	Error   string
	Success string
	// Masked display helpers
	SecretKeyMask    string // e.g. "****abcd" or ""
	ResticPWStatus   string // "configured" | "not set"
}

// HandleDRSettings renders and processes the Disaster Recovery configuration form (superadmin only).
func (s *Server) HandleDRSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.DB.GetDRConfig(s.AppKey)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	maskSecret := func(val string) string {
		if val == "" {
			return ""
		}
		if len(val) <= 4 {
			return "****"
		}
		return "****" + val[len(val)-4:]
	}
	resticStatus := "not set"
	if cfg.ResticPassword != "" {
		resticStatus = "configured"
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "dr_settings.html", drSettingsPageData{
			PageData:       s.newPageData(r),
			Config:         cfg,
			SecretKeyMask:  maskSecret(cfg.S3SecretKey),
			ResticPWStatus: resticStatus,
		})
		return
	}

	// POST
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	interval, _ := strconv.ParseUint(r.FormValue("default_interval_hours"), 10, 32)
	if interval == 0 {
		interval = 24
	}

	// Build config from form. Keep existing secrets when fields are left blank.
	newCfg := &models.DRConfig{
		S3Endpoint:           strings.TrimSpace(r.FormValue("s3_endpoint")),
		S3Bucket:             strings.TrimSpace(r.FormValue("s3_bucket")),
		S3Region:             strings.TrimSpace(r.FormValue("s3_region")),
		S3AccessKey:          strings.TrimSpace(r.FormValue("s3_access_key")),
		S3SecretKey:          r.FormValue("s3_secret_key"),
		ResticPassword:       r.FormValue("restic_password"),
		DefaultIntervalHours: uint32(interval),
	}

	// Keep existing secrets if the form field is blank (user didn't change them).
	if newCfg.S3AccessKey == "" {
		newCfg.S3AccessKey = cfg.S3AccessKey
	}
	if newCfg.S3SecretKey == "" {
		newCfg.S3SecretKey = cfg.S3SecretKey
	}
	if newCfg.ResticPassword == "" {
		newCfg.ResticPassword = cfg.ResticPassword
	}

	if err := s.DB.SaveDRConfig(newCfg, s.AppKey); err != nil {
		s.render(w, r, http.StatusOK, "dr_settings.html", drSettingsPageData{
			PageData:       s.newPageData(r),
			Config:         newCfg,
			SecretKeyMask:  maskSecret(newCfg.S3SecretKey),
			ResticPWStatus: resticStatus,
			Error:          "Failed to save configuration: " + err.Error(),
		})
		return
	}

	s.auditServer(r, "dr_config_saved", "warn", "save", "dr_config", "",
		"Disaster Recovery configuration updated", nil)

	http.SetCookie(w, &http.Cookie{Name: "flash", Value: "DR configuration saved.", Path: "/"})
	http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
}

// HandleDRNodeAction enables or disables DR for a specific node (superadmin only).
func (s *Server) HandleDRNodeAction(w http.ResponseWriter, r *http.Request, enable bool) {
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

	if err := s.DB.SetNodeDREnabled(node.ID, enable); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	action := "disable"
	msg := "Disaster Recovery disabled"
	if enable {
		action = "enable"
		msg = "Disaster Recovery enabled"
	}
	s.auditServer(r, "dr_node", "warn", action, "node", fmt.Sprintf("%d", node.ID),
		msg+" for node "+node.Name, nil)

	http.SetCookie(w, &http.Cookie{Name: "flash", Value: msg + " for " + node.Name, Path: "/"})
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// HandleDRRunNow sets the force_run flag so the node's next heartbeat triggers an immediate DR backup.
func (s *Server) HandleDRRunNow(w http.ResponseWriter, r *http.Request) {
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

	if err := s.DB.SetNodeDRForceRun(node.ID); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	s.auditServer(r, "dr_node", "warn", "force_run", "node", fmt.Sprintf("%d", node.ID),
		"DR force-run requested for node "+node.Name, nil)

	http.SetCookie(w, &http.Cookie{Name: "flash", Value: "DR backup requested for " + node.Name + ". It will run on the next heartbeat.", Path: "/"})
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}
