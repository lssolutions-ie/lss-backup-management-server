package models

import (
	"encoding/json"
	"time"
)

type User struct {
	ID           uint64
	Username     string
	PasswordHash string
	Role         string // "superadmin" | "user"
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) IsSuperAdmin() bool {
	return u.Role == "superadmin"
}

func (u *User) IsViewer() bool {
	return u.Role == "viewer"
}

// CanWrite returns true for superadmin and regular user roles.
// Viewers have read-only access to their assigned client groups.
func (u *User) CanWrite() bool {
	return u.Role == "superadmin" || u.Role == "user"
}

type ClientGroup struct {
	ID        uint64
	Name      string
	CreatedAt time.Time
	NodeCount int // populated by JOIN query
}

type Node struct {
	ID            uint64
	UID           string
	Name          string
	ClientGroupID uint64
	ClientGroup   string // populated by JOIN
	PSKEncrypted  string
	FirstSeenAt   *time.Time
	LastSeenAt    *time.Time
	CreatedAt     time.Time
}

func (n *Node) IsOnline() bool {
	if n.LastSeenAt == nil {
		return false
	}
	return time.Since(*n.LastSeenAt) < 10*time.Minute
}

func (n *Node) NeverSeen() bool {
	return n.FirstSeenAt == nil
}

type JobSnapshot struct {
	ID                     uint64
	NodeID                 uint64
	JobID                  string
	JobName                string
	Program                string
	Enabled                bool
	LastStatus             string
	LastRunAt              *time.Time
	LastRunDurationSeconds int
	LastError              string
	NextRunAt              *time.Time
	ScheduleDescription    string
	ConfigJSON             string // latest heartbeat-carried job config; empty if never received
	UpdatedAt              time.Time
}

type NodeReport struct {
	ID          uint64
	NodeID      uint64
	ReportedAt  time.Time
	ReceivedAt  time.Time
	ReportType  string // "heartbeat" | "post_run"
	PayloadJSON string
	JobCount    int    // computed from payload
	WorstStatus string // computed from payload
}

type Session struct {
	Token     string
	UserID    uint64
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NodeStatus is the decrypted inner payload sent by a node
type NodeStatus struct {
	PayloadVersion string      `json:"payload_version"`
	ReportType     string      `json:"report_type"` // "heartbeat" | "post_run"; empty treated as "post_run"
	NodeName       string      `json:"node_name"`
	ReportedAt     time.Time   `json:"reported_at"`
	Jobs           []JobStatus `json:"jobs"`
}

type JobStatus struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	Program                string          `json:"program"`
	Enabled                bool            `json:"enabled"`
	LastStatus             string          `json:"last_status"`
	LastRunAt              *time.Time      `json:"last_run_at,omitempty"`
	LastRunDurationSeconds int             `json:"last_run_duration_seconds"`
	LastError              string          `json:"last_error"`
	NextRunAt              *time.Time      `json:"next_run_at,omitempty"`
	ScheduleDescription    string          `json:"schedule_description"`
	Config                 json.RawMessage `json:"config,omitempty"` // heartbeat-only; opaque passthrough
}

// DashboardStats holds summary counters for the dashboard header cards
type DashboardStats struct {
	TotalNodes    int
	OnlineNodes   int
	FailingNodes  int
	NeverSeenNodes int
}

// NodeWithStatus is a Node enriched with computed status fields for the dashboard table
type NodeWithStatus struct {
	Node
	JobCount    int
	WorstStatus string // "success" | "failure" | "never_run" | ""
}

// GroupWithStats is a ClientGroup enriched with worst status for the dashboard cards
type GroupWithStats struct {
	ClientGroup
	WorstStatus string
}

// WorstStatus computes the worst job status across a slice of snapshots
func WorstStatus(jobs []JobSnapshot) string {
	worst := ""
	for _, j := range jobs {
		switch j.LastStatus {
		case "failure":
			return "failure"
		case "success":
			if worst == "" {
				worst = "success"
			}
		default:
			if worst != "success" {
				worst = "never_run"
			}
		}
	}
	return worst
}
