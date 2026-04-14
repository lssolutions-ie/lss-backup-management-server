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
		log.Printf("tuning: load: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		if err := s.DB.UpdateServerTuning(t); err != nil {
			log.Printf("tuning: save: %v", err)
			s.render(w, r, http.StatusInternalServerError, "tuning.html", tuningPageData{
				PageData: s.newPageData(r), Tuning: t, Error: "Failed to save settings.",
			})
			return
		}
		setFlash(w, "Server tuning updated.")
		http.Redirect(w, r, "/settings/tuning", http.StatusSeeOther)
		return
	}

	s.render(w, r, http.StatusOK, "tuning.html", tuningPageData{
		PageData: s.newPageData(r),
		Tuning:   t,
	})
}
