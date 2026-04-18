package web

import (
	"encoding/json"
	"net/http"

	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
	"github.com/lssolutions-ie/lss-backup-server/internal/worker"
)

// HandleServerBackupNow triggers an immediate server backup to S3.
func (s *Server) HandleServerBackupNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	lg := logx.FromContext(r.Context())
	lg.Warn("server backup: manual trigger")

	bw := worker.NewServerBackupWorker(s.DB, s.AppKey, s.Config.Database.DSN, s.Config.Security.SecretKeyFile, s.ConfigPath, s.Config.Terminal.SessionsDir)
	err := bw.RunOnce()
	if err != nil {
		lg.Error("server backup: manual trigger failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	s.auditServer(r, "server_backup_manual", "info", "backup", "server", "",
		"Manual server backup to S3 completed", nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}
