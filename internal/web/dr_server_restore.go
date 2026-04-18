package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
)

type resticSnapshot struct {
	ID       string   `json:"id"`
	ShortID  string   `json:"short_id"`
	Time     string   `json:"time"`
	Hostname string   `json:"hostname"`
	Paths    []string `json:"paths"`
}

func (s *Server) resticEnv() ([]string, string, error) {
	drCfg, err := s.DB.GetDRConfig(s.AppKey)
	if err != nil || drCfg == nil || drCfg.S3Endpoint == "" {
		return nil, "", fmt.Errorf("DR S3 config not set")
	}

	password := drCfg.ServerResticPassword
	if password == "" {
		password = drCfg.ResticPassword
	}
	if password == "" {
		return nil, "", fmt.Errorf("no restic password configured")
	}

	repo := fmt.Sprintf("s3:%s/%s/lss-backup-management-server", drCfg.S3Endpoint, drCfg.S3Bucket)
	env := append(os.Environ(),
		"RESTIC_REPOSITORY="+repo,
		"RESTIC_PASSWORD="+password,
		"AWS_ACCESS_KEY_ID="+drCfg.S3AccessKey,
		"AWS_SECRET_ACCESS_KEY="+drCfg.S3SecretKey,
	)
	if drCfg.S3Region != "" {
		env = append(env, "AWS_DEFAULT_REGION="+drCfg.S3Region)
	}

	resticBin := "/usr/bin/restic"
	if p, err := exec.LookPath("restic"); err == nil {
		resticBin = p
	}

	return env, resticBin, nil
}

// HandleDRServerSnapshots lists all server backup snapshots as JSON.
func (s *Server) HandleDRServerSnapshots(w http.ResponseWriter, r *http.Request) {
	env, resticBin, err := s.resticEnv()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	cmd := exec.Command(resticBin, "snapshots", "--json")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to list snapshots: " + err.Error()})
		return
	}

	var snapshots []resticSnapshot
	json.Unmarshal(out, &snapshots)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"snapshots": snapshots})
}

// HandleDRServerRestore restores the server from a specific restic snapshot.
func (s *Server) HandleDRServerRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	snapshotID := strings.TrimSpace(r.FormValue("snapshot_id"))
	if snapshotID == "" {
		setFlash(w, "No snapshot selected.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	lg := logx.FromContext(r.Context())
	lg.Warn("server restore: starting", "snapshot_id", snapshotID)

	s.auditServer(r, "server_restore_initiated", "critical", "restore", "system", snapshotID,
		"Server restore initiated from snapshot "+snapshotID, nil)

	env, resticBin, err := s.resticEnv()
	if err != nil {
		setFlash(w, "DR config error: "+err.Error())
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	tmpDir, err := os.MkdirTemp("", "lss-server-restore-*")
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	defer os.RemoveAll(tmpDir)

	restoreCmd := exec.Command(resticBin, "restore", snapshotID, "--target", tmpDir)
	restoreCmd.Env = env
	restoreOut, err := restoreCmd.CombinedOutput()
	if err != nil {
		lg.Error("server restore: restic restore failed", "err", err.Error(), "output", string(restoreOut))
		setFlash(w, "Restore failed: "+err.Error())
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}
	lg.Info("server restore: snapshot extracted", "snapshot_id", snapshotID)

	dumpPath := filepath.Join(tmpDir, "dump.sql")
	if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
		lg.Error("server restore: dump.sql not found in snapshot")
		setFlash(w, "Restore failed: dump.sql not found in snapshot.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}

	dsn, err := parseDSN(s.Config.Database.DSN)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	importCmd := exec.Command("mysql",
		"-u", dsn.User, "-p"+dsn.Password,
		"-h", dsn.Host, "-P", dsn.Port, dsn.DBName,
	)
	dumpInput, err := os.Open(dumpPath)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	importCmd.Stdin = dumpInput
	importCmd.Stderr = io.Discard
	if err := importCmd.Run(); err != nil {
		dumpInput.Close()
		lg.Error("server restore: mysql import failed", "err", err.Error())
		setFlash(w, "Restore failed: database import error.")
		http.Redirect(w, r, "/settings/node-disaster-recovery", http.StatusSeeOther)
		return
	}
	dumpInput.Close()
	lg.Info("server restore: database imported")

	keyPath := filepath.Join(tmpDir, "secret.key")
	if _, err := os.Stat(keyPath); err == nil {
		copyFileRestore(keyPath, s.Config.Security.SecretKeyFile)
		lg.Info("server restore: secret.key restored")
	}

	sessDir := s.Config.Terminal.SessionsDir
	restoreSessDir := filepath.Join(tmpDir, "sessions")
	if sessDir != "" {
		if entries, err := os.ReadDir(restoreSessDir); err == nil {
			os.MkdirAll(sessDir, 0o755)
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".cast") {
					copyFileRestore(filepath.Join(restoreSessDir, e.Name()), filepath.Join(sessDir, e.Name()))
				}
			}
			lg.Info("server restore: session recordings restored")
		}
	}

	s.DB.RawExec("DELETE FROM sessions")
	s.DB.RawExec("UPDATE users SET force_setup = 1, totp_secret = '', totp_enabled = 0 WHERE role = 'superadmin'")

	s.DB.RawExec(
		"INSERT INTO audit_log (ts, source, category, severity, actor, action, entity_type, message) VALUES (NOW(), 'server', 'system_restored', 'critical', 'system', 'restore', 'system', ?)",
		fmt.Sprintf("System restored from DR snapshot %s", snapshotID),
	)
	lg.Info("server restore: completed", "snapshot_id", snapshotID)

	setFlash(w, "System restored from snapshot "+snapshotID+". Please log in and set a new password.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func copyFileRestore(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}
