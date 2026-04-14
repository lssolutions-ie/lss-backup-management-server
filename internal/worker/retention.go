package worker

import (
	"log"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
)

// RetentionWorker runs periodically to aggregate old node_reports into
// job_daily_stats and prune the raw history according to server_tuning.
type RetentionWorker struct {
	db       *db.DB
	interval time.Duration
}

func NewRetentionWorker(d *db.DB) *RetentionWorker {
	return &RetentionWorker{db: d, interval: 1 * time.Hour}
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
		log.Printf("retention: get tuning: %v", err)
		return
	}
	// Step 1: aggregate anything older than retention_raw_days into daily stats.
	if n, err := w.db.AggregateDailyStats(tuning.RetentionRawDays); err != nil {
		log.Printf("retention: aggregate: %v", err)
	} else if n > 0 {
		log.Printf("retention: aggregated %d job-day rows beyond %d days", n, tuning.RetentionRawDays)
	}
	// Step 2: prune heartbeats older than raw cutoff.
	if n, err := w.db.PruneHeartbeatReports(tuning.RetentionRawDays); err != nil {
		log.Printf("retention: prune heartbeats: %v", err)
	} else if n > 0 {
		log.Printf("retention: pruned %d heartbeat reports older than %d days", n, tuning.RetentionRawDays)
	}
	// Step 3: prune everything older than post_run cutoff.
	if n, err := w.db.PruneAllReports(tuning.RetentionPostRunDays); err != nil {
		log.Printf("retention: prune all: %v", err)
	} else if n > 0 {
		log.Printf("retention: pruned %d reports older than %d days", n, tuning.RetentionPostRunDays)
	}
}
