package web

import (
	"net/http"
	"strconv"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

// HandleIntelligenceTuning renders and saves intelligence-specific tuning (anomaly thresholds + retention).
func (s *Server) HandleIntelligenceTuning(w http.ResponseWriter, r *http.Request) {
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
		t.AnomalySnapshotDropThreshold = parse("anomaly_snapshot_drop_threshold", t.AnomalySnapshotDropThreshold)
		t.AnomalyFilesDropPct = parse("anomaly_files_drop_pct", t.AnomalyFilesDropPct)
		t.AnomalyFilesDropMin = parse("anomaly_files_drop_min", t.AnomalyFilesDropMin)
		t.AnomalyBytesDropPct = parse("anomaly_bytes_drop_pct", t.AnomalyBytesDropPct)
		t.AnomalyBytesDropMinMB = parse("anomaly_bytes_drop_min_mb", t.AnomalyBytesDropMinMB)
		t.AnomalyAckRetentionDays = parse("anomaly_ack_retention_days", t.AnomalyAckRetentionDays)
		if err := s.DB.UpdateServerTuning(t); err != nil {
			logx.FromContext(r.Context()).Error("save intelligence tuning failed", "err", err.Error())
			s.render(w, r, http.StatusInternalServerError, "intelligence_tuning.html", tuningPageData{
				PageData: s.newPageData(r), Tuning: t, Error: "Failed to save settings.",
			})
			return
		}
		s.auditServer(r, "intelligence_tuning_saved", "warn", "save", "tuning", "",
			"Updated intelligence tuning settings",
			map[string]string{
				"anomaly_snapshot_drop_threshold": strconv.FormatUint(uint64(t.AnomalySnapshotDropThreshold), 10),
				"anomaly_files_drop_pct":          strconv.FormatUint(uint64(t.AnomalyFilesDropPct), 10),
				"anomaly_ack_retention_days":       strconv.FormatUint(uint64(t.AnomalyAckRetentionDays), 10),
			})
		setFlash(w, "Intelligence tuning updated.")
		http.Redirect(w, r, "/settings/intelligence", http.StatusSeeOther)
		return
	}

	s.render(w, r, http.StatusOK, "intelligence_tuning.html", tuningPageData{
		PageData: s.newPageData(r),
		Tuning:   t,
	})
}
