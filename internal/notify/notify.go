package notify

import (
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/models"
)

// Notifier is the alerting interface. Implement it to add email/webhook alerts.
type Notifier interface {
	NotifyJobFailure(node models.Node, job models.JobSnapshot) error
	NotifyNodeOffline(node models.Node, lastSeen time.Time) error
}

// NoOpNotifier satisfies the Notifier interface with no-op implementations.
type NoOpNotifier struct{}

func (n NoOpNotifier) NotifyJobFailure(node models.Node, job models.JobSnapshot) error {
	return nil
}

func (n NoOpNotifier) NotifyNodeOffline(node models.Node, lastSeen time.Time) error {
	return nil
}
