package models

import (
	"encoding/json"
	"fmt"
	"time"
)

type User struct {
	ID           uint64
	Username     string
	Email        *string // nullable
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	ForceSetup   bool   // true = must change password and enable 2FA before using dashboard
	Role         string // "superadmin" | "manager" | "user" | "guest"
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Tags         []Tag  // populated separately
}

// EmailStr returns the email or empty string if nil.
func (u *User) EmailStr() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}

func (u *User) IsSuperAdmin() bool {
	return u.Role == "superadmin"
}

func (u *User) IsManager() bool {
	return u.Role == "manager"
}

func (u *User) IsUser() bool {
	return u.Role == "user"
}

func (u *User) IsGuest() bool {
	return u.Role == "guest"
}

// CanWrite returns true for superadmin and manager roles.
// These roles can register/edit/delete nodes, manage tags, etc.
func (u *User) CanWrite() bool {
	return u.Role == "superadmin" || u.Role == "manager"
}

// CanManageUsers returns true for roles that can create/edit/delete users and groups.
func (u *User) CanManageUsers() bool {
	return u.Role == "superadmin" || u.Role == "manager"
}

// CanTerminal returns true for roles that can open SSH terminal sessions.
func (u *User) CanTerminal() bool {
	return u.Role == "superadmin" || u.Role == "manager"
}

// CanBrowseRepo returns true for roles that can browse snapshots and download files.
// Guests can only view jobs, not snapshot contents.
func (u *User) CanBrowseRepo() bool {
	return u.Role != "guest"
}

// IsGroupScoped returns true if this user's dashboard is scoped to assigned groups.
// Superadmins and managers see all nodes.
func (u *User) IsGroupScoped() bool {
	return u.Role == "user" || u.Role == "guest"
}

type ClientGroup struct {
	ID        uint64
	Name      string
	Rank      string // "bronze" | "silver" | "gold" | "diamond"
	CreatedAt time.Time
	NodeCount int // populated by JOIN query
}

// RankLabel returns a display-friendly label for the rank.
func (g *ClientGroup) RankLabel() string {
	switch g.Rank {
	case "diamond":
		return "Diamond"
	case "gold":
		return "Gold"
	case "silver":
		return "Silver"
	default:
		return "Bronze"
	}
}

// RankColor returns a badge color class for the rank.
func (g *ClientGroup) RankColor() string {
	switch g.Rank {
	case "diamond":
		return "#b9f2ff"
	case "gold":
		return "#ffd700"
	case "silver":
		return "#c0c0c0"
	default:
		return "#cd7f32"
	}
}

type Node struct {
	ID              uint64
	UID             string
	Name            string
	ClientGroupID   uint64
	ClientGroup     string // populated by JOIN
	PSKEncrypted    string
	FirstSeenAt     *time.Time
	LastSeenAt      *time.Time
	TunnelPort      *int   // last-reported reverse-tunnel port on the mgmt server
	TunnelConnected bool   // last-reported tunnel-connected flag from the node
	TunnelPublicKey string // ssh public key registered for the reverse tunnel
	CreatedAt       time.Time
	// Hardware info (updated on each heartbeat)
	HwOS       string
	HwArch     string
	HwCPUs     int
	HwHostname string
	HwRAMBytes int64
	HwLANIP    string
	HwPublicIP string
	HwStorageJSON string // JSON array of StorageInfo
	Tags          []Tag  // populated separately, not from the main query
}

// TunnelReady returns true if the server can dial 127.0.0.1:TunnelPort and expect to reach the node.
func (n *Node) TunnelReady() bool {
	return n.TunnelConnected && n.TunnelPort != nil && *n.TunnelPort > 0
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

// HwRAMFormatted returns RAM in a human-readable format (e.g. "16.0 GB").
func (n *Node) HwRAMFormatted() string {
	if n.HwRAMBytes == 0 {
		return ""
	}
	gb := float64(n.HwRAMBytes) / (1024 * 1024 * 1024)
	return fmt.Sprintf("%.1f GB", gb)
}

// HwStorage parses the stored JSON into a slice of StorageInfo.
func (n *Node) HwStorage() []StorageInfo {
	if n.HwStorageJSON == "" {
		return nil
	}
	var s []StorageInfo
	_ = json.Unmarshal([]byte(n.HwStorageJSON), &s)
	return s
}

// HwOSFormatted returns a user-friendly OS name.
func (n *Node) HwOSFormatted() string {
	switch n.HwOS {
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return n.HwOS
	}
}

// HasHardware returns true if hardware info has been reported.
func (n *Node) HasHardware() bool {
	return n.HwOS != ""
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
	Token        string
	UserID       uint64
	ExpiresAt    time.Time
	LastActiveAt time.Time
	CreatedAt    time.Time
}

// NodeStatus is the decrypted inner payload sent by a node
type NodeStatus struct {
	PayloadVersion string        `json:"payload_version"`
	ReportType     string        `json:"report_type"` // "heartbeat" | "post_run"; empty treated as "post_run"
	NodeName       string        `json:"node_name"`
	ReportedAt     time.Time     `json:"reported_at"`
	Jobs           []JobStatus   `json:"jobs"`
	Tunnel         *TunnelInfo   `json:"tunnel,omitempty"`
	Hardware       *HardwareInfo `json:"hardware,omitempty"`
}

// HardwareInfo is collected on heartbeats (not post_run).
type HardwareInfo struct {
	OS       string        `json:"os"`        // "linux", "darwin", "windows"
	Arch     string        `json:"arch"`      // "amd64", "arm64"
	CPUs     int           `json:"cpus"`      // logical CPU count
	Hostname string        `json:"hostname"`
	RAMBytes int64         `json:"ram_bytes"`
	Storage  []StorageInfo `json:"storage"`
	LANIP    string        `json:"lan_ip"`
	PublicIP string        `json:"public_ip"`
}

// StorageInfo represents a single disk/mount point.
type StorageInfo struct {
	Path       string `json:"path"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
}

// TunnelInfo is carried on heartbeats by nodes running the reverse-tunnel daemon.
type TunnelInfo struct {
	Port      int    `json:"port"`       // port on the mgmt-server that reverse-forwards to the node's sshd
	PublicKey string `json:"public_key"` // ssh public key the node uses to hold the tunnel open
	Connected bool   `json:"connected"`  // true if the tunnel is currently established
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

// SMTPConfig holds email server configuration.
type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	PasswordEnc string // AES-encrypted
	FromAddress string
	FromName    string
	UseTLS      bool
	Enabled     bool
}

// Tag represents a user-defined label that can be attached to nodes.
type Tag struct {
	ID        uint64
	Name      string
	Color     string // background hex color e.g. "#206bc4"
	TextColor string // text hex color e.g. "#ffffff"
}

// ReportFilter holds query parameters for filtering check-in history.
type ReportFilter struct {
	NodeID uint64
	Type   string // "heartbeat" | "post_run" | "" (all)
	Status string // "success" | "failure" | "never_run" | "" (all)
	From   string // date string YYYY-MM-DD
	To     string // date string YYYY-MM-DD
	Limit  int
	Offset int
}

// DashboardStats holds summary counters for the dashboard header cards
type DashboardStats struct {
	TotalNodes     int
	OnlineNodes    int
	FailingNodes   int
	WarningNodes   int
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
	WorstStatus    string
	SuccessJobs    int
	FailureJobs    int
	WarningJobs    int
	NeverRunJobs   int
}

// TotalJobs returns the sum of all job categories.
func (g *GroupWithStats) TotalJobs() int {
	return g.SuccessJobs + g.FailureJobs + g.WarningJobs + g.NeverRunJobs
}

// SuccessRate returns the success percentage (0-100). Returns 0 if no jobs.
func (g *GroupWithStats) SuccessRate() int {
	total := g.TotalJobs()
	if total == 0 {
		return 0
	}
	return g.SuccessJobs * 100 / total
}

// WorstStatus computes the worst job status across a slice of snapshots
func WorstStatus(jobs []JobSnapshot) string {
	worst := ""
	for _, j := range jobs {
		switch j.LastStatus {
		case "failure":
			return "failure"
		case "warning":
			if worst != "failure" {
				worst = "warning"
			}
		case "success":
			if worst == "" {
				worst = "success"
			}
		default:
			if worst != "success" && worst != "warning" {
				worst = "never_run"
			}
		}
	}
	return worst
}
