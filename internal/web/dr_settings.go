package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type drSettingsPageData struct {
	PageData
	Config *models.DRConfig
	Tuning *models.ServerTuning
	Error  string
}

func (s *Server) HandleDRSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.DB.GetDRConfig(s.AppKey)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	tuning, _ := s.DB.GetServerTuning()

	s.render(w, r, http.StatusOK, "dr_settings.html", drSettingsPageData{
		PageData: s.newPageData(r),
		Config:   cfg,
		Tuning:   tuning,
	})
}

// HandleDRSaveS3 saves the global S3 configuration.
func (s *Server) HandleDRSaveS3(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	cfg, _ := s.DB.GetDRConfig(s.AppKey)

	endpoint := strings.TrimSpace(r.FormValue("s3_endpoint"))
	bucket := strings.TrimSpace(r.FormValue("s3_bucket"))
	region := strings.TrimSpace(r.FormValue("s3_region"))
	accessKey := strings.TrimSpace(r.FormValue("s3_access_key"))
	secretKey := r.FormValue("s3_secret_key")

	if accessKey == "" {
		accessKey = cfg.S3AccessKey
	}
	if secretKey == "" {
		secretKey = cfg.S3SecretKey
	}

	if err := s.DB.SaveDRS3Config(endpoint, bucket, region, accessKey, secretKey, s.AppKey); err != nil {
		logx.FromContext(r.Context()).Error("save DR S3 config failed", "err", err.Error())
		setFlash(w, "Failed to save S3 configuration.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	s.auditServer(r, "dr_s3_config_saved", "warn", "save", "dr_config", "",
		"DR S3 configuration updated", map[string]string{
			"endpoint": endpoint, "bucket": bucket, "region": region,
		})
	setFlash(w, "S3 configuration saved. All nodes will pick up the new config on their next heartbeat.")
	http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
}

// HandleDRSaveServer saves server backup restic password and retention.
func (s *Server) HandleDRSaveServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	cfg, _ := s.DB.GetDRConfig(s.AppKey)

	password := r.FormValue("server_restic_password")
	if password == "" {
		password = cfg.ServerResticPassword
	}
	keepLast, _ := strconv.ParseUint(r.FormValue("server_keep_last"), 10, 32)
	keepDaily, _ := strconv.ParseUint(r.FormValue("server_keep_daily"), 10, 32)
	interval, _ := strconv.ParseUint(r.FormValue("server_backup_interval_hours"), 10, 32)
	if keepLast == 0 {
		keepLast = 7
	}
	if keepDaily == 0 {
		keepDaily = 30
	}
	if interval == 0 {
		interval = 24
	}

	if err := s.DB.SaveDRServerConfig(password, uint32(keepLast), uint32(keepDaily), s.AppKey); err != nil {
		logx.FromContext(r.Context()).Error("save DR server config failed", "err", err.Error())
		setFlash(w, "Failed to save server backup configuration.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	// Update interval in server_tuning
	s.DB.RawExec("UPDATE server_tuning SET server_backup_interval_hours = ? WHERE id = 1", uint32(interval))

	s.auditServer(r, "dr_server_config_saved", "warn", "save", "dr_config", "",
		"Server backup configuration updated", nil)
	setFlash(w, "Server backup configuration saved.")
	http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
}

// HandleDRSaveNode saves node backup restic password, interval, and retention.
func (s *Server) HandleDRSaveNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	cfg, _ := s.DB.GetDRConfig(s.AppKey)

	password := r.FormValue("node_restic_password")
	if password == "" {
		password = cfg.ResticPassword
	}
	interval, _ := strconv.ParseUint(r.FormValue("default_interval_hours"), 10, 32)
	keepLast, _ := strconv.ParseUint(r.FormValue("node_keep_last"), 10, 32)
	keepDaily, _ := strconv.ParseUint(r.FormValue("node_keep_daily"), 10, 32)
	if interval == 0 {
		interval = 24
	}
	if keepLast == 0 {
		keepLast = 7
	}
	if keepDaily == 0 {
		keepDaily = 30
	}

	if err := s.DB.SaveDRNodeConfig(password, uint32(interval), uint32(keepLast), uint32(keepDaily), s.AppKey); err != nil {
		logx.FromContext(r.Context()).Error("save DR node config failed", "err", err.Error())
		setFlash(w, "Failed to save node backup configuration.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	s.auditServer(r, "dr_node_config_saved", "warn", "save", "dr_config", "",
		"Node backup configuration updated", nil)
	setFlash(w, "Node backup configuration saved. Nodes will pick up changes on next heartbeat.")
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

// HandleDRRunNow SSHes to the node via tunnel and runs DR backup immediately.
// Falls back to heartbeat flag if SSH creds aren't provided.
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

	// Try SSH-based instant execution (same pattern as CLI update)
	if node.TunnelReady() {
		body, _ := io.ReadAll(r.Body)
		username, password := s.getRepoSSHCreds(r, node.ID, body)
		if username == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "ssh_creds_required"})
			return
		}

		cmd := fmt.Sprintf("%s --dr-run-now", cliPath(node.HwOS))
		output, err := sshExecOnNodeSudo(node, username, password, cmd)
		if err != nil {
			logx.FromContext(r.Context()).Error("dr run-now failed",
				"node_id", node.ID, "err", err.Error())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "DR backup failed: " + err.Error(),
				"output": string(output),
			})
			return
		}

		s.auditServer(r, "dr_run_now", "info", "dr_run", "node",
			fmt.Sprintf("%d", node.ID),
			"Immediate DR backup executed on "+node.Name, nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"ok":     "true",
			"output": string(output),
		})
		return
	}

	// No tunnel — fall back to heartbeat flag
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := s.DB.SetNodeDRForceRun(node.ID); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	s.auditServer(r, "dr_node", "warn", "force_run", "node", fmt.Sprintf("%d", node.ID),
		"DR force-run requested for node "+node.Name+" (heartbeat)", nil)
	setFlash(w, "DR backup requested for "+node.Name+". It will run on the next heartbeat.")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}
