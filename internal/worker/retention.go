package worker

import (
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/db"
	"github.com/lssolutions-ie/lss-backup-server/internal/recorder"
)

// RetentionWorker runs periodically to aggregate old node_reports into
// job_daily_stats and prune the raw history according to server_tuning.
type RetentionWorker struct {
	db          *db.DB
	sessionsDir string
	interval    time.Duration
}

func NewRetentionWorker(d *db.DB, sessionsDir string) *RetentionWorker {
	return &RetentionWorker{db: d, sessionsDir: sessionsDir, interval: 1 * time.Hour}
}

func (w *RetentionWorker) Start() {
	go w.run()
}

func (w *RetentionWorker) run() {
	// Run once on startup, then on the interval.
	w.tick()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for range t.C {
		w.tick()
	}
}

func (w *RetentionWorker) tick() {
	tuning, err := w.db.GetServerTuning()
	if err != nil {
		lg.Error("get tuning failed", "err", err.Error())
		return
	}
	// Step 1: aggregate anything older than retention_raw_days into daily stats.
	if n, err := w.db.AggregateDailyStats(tuning.RetentionRawDays); err != nil {
		lg.Error("aggregate failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("aggregated job-day rows", "count", n, "beyond_days", tuning.RetentionRawDays)
	}
	// Step 2: prune heartbeats older than raw cutoff.
	if n, err := w.db.PruneHeartbeatReports(tuning.RetentionRawDays); err != nil {
		lg.Error("prune heartbeats failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("pruned heartbeat reports", "count", n, "older_than_days", tuning.RetentionRawDays)
	}
	// Step 3: prune everything older than post_run cutoff.
	if n, err := w.db.PruneAllReports(tuning.RetentionPostRunDays); err != nil {
		lg.Error("prune all reports failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("pruned reports", "count", n, "older_than_days", tuning.RetentionPostRunDays)
	}
	// Step 4: prune audit_log rows older than configured retention (0 = forever).
	if n, err := w.db.PruneAuditLog(tuning.AuditRetentionDays); err != nil {
		lg.Error("prune audit failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("pruned audit rows", "count", n, "older_than_days", tuning.AuditRetentionDays)
	}
	// Step 5: prune terminal session .cast recordings.
	if n, err := recorder.PruneOlderThan(w.sessionsDir, tuning.TerminalRecordingRetentionDays); err != nil {
		lg.Error("prune recordings failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("pruned session recordings", "count", n, "older_than_days", tuning.TerminalRecordingRetentionDays)
	}
	// Step 6: prune pending nodes whose install tokens expired 24h+ ago and
	// never completed registration (first_seen_at IS NULL).
	if n, err := w.db.PruneExpiredPendingNodes(); err != nil {
		lg.Error("prune pending nodes failed", "err", err.Error())
	} else if n > 0 {
		lg.Info("pruned expired pending nodes", "count", n)
	}
}
