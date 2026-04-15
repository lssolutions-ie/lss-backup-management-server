package web

import (
	"log"
	"net/http"
	"strconv"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type tuningPageData struct {
	PageData
	Tuning  *models.ServerTuning
	Success string
	Error   string
}

// HandleServerTuning renders and saves global server tuning settings. Superadmin only.
func (s *Server) HandleServerTuning(w http.ResponseWriter, r *http.Request) {
	t, err := s.DB.GetServerTuning()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	if r.Method == http.MethodPost {
		if !s.validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		parse := func(field string, def uint32) uint32 {
			v, err := strconv.ParseUint(r.FormValue(field), 10, 32)
			if err != nil {
				return def
			}
			return uint32(v)
		}
		t.RepoStatsIntervalSeconds = parse("repo_stats_interval_seconds", t.RepoStatsIntervalSeconds)
		t.RepoStatsTimeoutSeconds = parse("repo_stats_timeout_seconds", t.RepoStatsTimeoutSeconds)
		t.RetentionRawDays = parse("retention_raw_days", t.RetentionRawDays)
		t.RetentionPostRunDays = parse("retention_post_run_days", t.RetentionPostRunDays)
		t.OfflineThresholdMinutes = parse("offline_threshold_minutes", t.OfflineThresholdMinutes)
		t.OfflineCheckIntervalMinutes = parse("offline_check_interval_minutes", t.OfflineCheckIntervalMinutes)
		t.DefaultSilenceSeconds = parse("default_silence_seconds", t.DefaultSilenceSeconds)
		t.AnomalySnapshotDropThreshold = parse("anomaly_snapshot_drop_threshold", t.AnomalySnapshotDropThreshold)
		t.AnomalyFilesDropPct = parse("anomaly_files_drop_pct", t.AnomalyFilesDropPct)
		t.AnomalyFilesDropMin = parse("anomaly_files_drop_min", t.AnomalyFilesDropMin)
		t.AnomalyBytesDropPct = parse("anomaly_bytes_drop_pct", t.AnomalyBytesDropPct)
		t.AnomalyBytesDropMinMB = parse("anomaly_bytes_drop_min_mb", t.AnomalyBytesDropMinMB)
		t.AnomalyAckRetentionDays = parse("anomaly_ack_retention_days", t.AnomalyAckRetentionDays)
		t.AuditRetentionDays = parse("audit_retention_days", t.AuditRetentionDays)
		t.TerminalRecordingEnabled = r.FormValue("terminal_recording_enabled") == "1"
		t.TerminalRecordingRetentionDays = parse("terminal_recording_retention_days", t.TerminalRecordingRetentionDays)
		if err := s.DB.UpdateServerTuning(t); err != nil {
			log.Printf("tuning: save: %v", err)
			s.render(w, r, http.StatusInternalServerError, "tuning.html", tuningPageData{
				PageData: s.newPageData(r), Tuning: t, Error: "Failed to save settings.",
			})
			return
		}
		s.auditServer(r, "tuning_saved", "warn", "save", "tuning", "",
			"Updated server tuning settings",
			map[string]string{
				"offline_threshold_minutes": strconv.FormatUint(uint64(t.OfflineThresholdMinutes), 10),
				"retention_raw_days":        strconv.FormatUint(uint64(t.RetentionRawDays), 10),
				"audit_retention_days":      strconv.FormatUint(uint64(t.AuditRetentionDays), 10),
			})
		setFlash(w, "Server tuning updated.")
		http.Redirect(w, r, "/settings/tuning", http.StatusSeeOther)
		return
	}

	s.render(w, r, http.StatusOK, "tuning.html", tuningPageData{
		PageData: s.newPageData(r),
		Tuning:   t,
	})
}
