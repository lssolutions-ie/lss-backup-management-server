package worker

import (
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
)

var lg = logx.Component("worker")

// OfflineChecker periodically queries for nodes that haven't checked in recently
// and calls the notifier for each one.
type OfflineChecker struct {
	db       *db.DB
	notifier notify.Notifier
	interval time.Duration
}

func NewOfflineChecker(d *db.DB, n notify.Notifier) *OfflineChecker {
	return &OfflineChecker{
		db:       d,
		notifier: n,
		interval: 5 * time.Minute,
	}
}

// Start launches the checker in a goroutine. Call once at startup.
func (c *OfflineChecker) Start() {
	go c.run()
}

func (c *OfflineChecker) run() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for range ticker.C {
		c.check()
	}
}

func (c *OfflineChecker) check() {
	nodes, err := c.db.ListOfflineNodes()
	if err != nil {
		lg.Error("list offline nodes failed", "err", err.Error())
		return
	}
	for _, node := range nodes {
		lastSeen := time.Time{}
		if node.LastSeenAt != nil {
			lastSeen = *node.LastSeenAt
		}
		lg.Warn("node offline", "name", node.Name, "uid", node.UID, "last_seen", lastSeen)
		if err := c.notifier.NotifyNodeOffline(*node, lastSeen); err != nil {
			lg.Error("notify offline failed", "uid", node.UID, "err", err.Error())
		}
	}
}
