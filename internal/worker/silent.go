package worker

import (
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
)

// SilentNodeChecker fires an audit_log event when a node misses a heartbeat
// within the SilentAlertThresholdMinutes window — much sooner than the
// existing OfflineChecker (default 10 min). The intent is to flag attacker-
// stopped daemons fast enough that an operator might catch them in the act.
//
// Dedup: we don't want to spam. Each silence transition fires exactly one
// audit_log row of category=node_silent. The next successful heartbeat clears
// the state by virtue of advancing last_seen_at past the audit row's ts.
type SilentNodeChecker struct {
	db       *db.DB
	interval time.Duration
}

func NewSilentNodeChecker(d *db.DB) *SilentNodeChecker {
	return &SilentNodeChecker{db: d, interval: 1 * time.Minute}
}

func (c *SilentNodeChecker) Start() {
	go c.run()
}

func (c *SilentNodeChecker) run() {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for range t.C {
		c.tick()
	}
}

func (c *SilentNodeChecker) tick() {
	tuning, err := c.db.GetServerTuning()
	if err != nil {
		lg.Error("silent: get tuning failed", "err", err.Error())
		return
	}
	threshold := tuning.SilentAlertThresholdMinutes
	if threshold == 0 {
		return // disabled
	}
	if err := c.db.FireSilentNodeAlerts(threshold); err != nil {
		lg.Error("silent: fire alerts failed", "err", err.Error())
	}
}

// FireSilentNodeAlerts is implemented in internal/db/audit.go; it inserts one
// audit_log row per node that just went silent, dedup'd against existing
// alerts since last_seen_at.
