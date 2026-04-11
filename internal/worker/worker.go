package worker

import (
	"log"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
)

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
		log.Printf("worker: list offline nodes: %v", err)
		return
	}
	for _, node := range nodes {
		lastSeen := time.Time{}
		if node.LastSeenAt != nil {
			lastSeen = *node.LastSeenAt
		}
		log.Printf("worker: node %q (uid=%s) is offline, last seen: %v", node.Name, node.UID, lastSeen)
		if err := c.notifier.NotifyNodeOffline(*node, lastSeen); err != nil {
			log.Printf("worker: notify offline %s: %v", node.UID, err)
		}
	}
}
