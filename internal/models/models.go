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
	UserTags     []UserTag // populated separately
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

	// CLI version tracking
	CLIVersion       string
	CLIUpdatePending bool

	// Disaster Recovery (DR) state — per-node, updated via heartbeat
	DREnabled       bool
	DRIntervalHours uint32
	DRLastBackupAt  *time.Time
	DRLastStatus    string
	DRLastError     string
	DRSnapshotCount uint32
	DRForceRun      bool
	DRConfigVersion uint32

	// Graceful deletion flow
	DeletionPhase      string // "" | "export_pending" | "export_received" | "uninstall_pending"
	SecretsExportEnc   string // AES-encrypted JSON blob of exported secrets
	DeletionRetainData bool   // if true, CLI keeps backup data on disk during uninstall
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

	// Extended from CLI v2.2.0+
	BytesTotal           uint64
	BytesNew             uint64
	FilesTotal           uint64
	FilesNew             uint64
	SnapshotID           string
	SnapshotIDs          []string   // restic snapshot ID set, persisted as JSON. Diffed across runs to catch single-snapshot forget.
	RepoSizeObserved     uint64     // authoritative from `restic stats`
	RepoSizeEstimated    uint64     // running: observed + sum of bytes_new since
	RepoSizeObservedAt   *time.Time // when we last got an authoritative reading
	ErrorCategory        string     // server-classified (network/auth/disk_full/...)
	RepoStatsIntervalSec uint32     // 0 = inherit global, non-zero = per-job override
	SnapshotCount        uint32     // restic snapshot count (most recent)
}

// AnomalyType enumerates security-relevant deltas we flag.
type AnomalyType string

const (
	AnomalySnapshotDrop AnomalyType = "snapshot_drop"
	AnomalyFilesDrop    AnomalyType = "files_drop"
	AnomalyBytesDrop    AnomalyType = "bytes_drop"
)

// JobAnomaly is one row in the audit log.
type JobAnomaly struct {
	ID             uint64
	NodeID         uint64
	JobID          string
	DetectedAt     time.Time
	AnomalyType    AnomalyType
	PrevValue      int64
	CurrValue      int64
	DeltaValue     int64
	DeltaPct       float64
	SnapshotID     string
	PrevSnapshotID string // for forensics — the snapshot we were comparing against
	CurrSnapshotID string // the snapshot the run produced (same as SnapshotID for files/bytes drops)
	Acknowledged   bool
	AcknowledgedBy *uint64
	AcknowledgedAt *time.Time
	ResolutionNote string
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
	CLIVersion     string          `json:"cli_version,omitempty"`
	AuditEvents    []AuditEvent    `json:"audit_events,omitempty"` // v3+
	DRStatus       *DRStatus       `json:"dr_status,omitempty"`
	SecretsExport  json.RawMessage `json:"secrets_export,omitempty"` // opaque blob from CLI during graceful deletion
}

// DRConfig is the single-row global DR configuration.
type DRConfig struct {
	S3Endpoint           string
	S3Bucket             string
	S3Region             string
	S3AccessKey          string // decrypted
	S3SecretKey          string // decrypted
	ResticPassword       string // decrypted
	DefaultIntervalHours uint32
	ConfigVersion        uint32
}

// DRStatus is what the CLI reports in each heartbeat.
type DRStatus struct {
	Configured    bool   `json:"configured"`
	ConfigVersion uint32 `json:"config_version"`
	LastBackupAt  string `json:"last_backup_at,omitempty"` // ISO8601
	Status        string `json:"status"`                   // "success" | "failure" | ""
	Error         string `json:"error,omitempty"`
	SnapshotCount uint32 `json:"snapshot_count"`
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
	LastStatus             string          `json:"last_status"` // success|warning|failure|skipped|cancelled|paused|""
	LastRunAt              *time.Time      `json:"last_run_at,omitempty"`
	LastRunDurationSeconds int             `json:"last_run_duration_seconds"`
	LastError              string          `json:"last_error"`
	NextRunAt              *time.Time      `json:"next_run_at,omitempty"`
	ScheduleDescription    string          `json:"schedule_description"`
	Config                 json.RawMessage `json:"config,omitempty"` // heartbeat-only; opaque passthrough

	// Extended fields (v2.2.0+ CLI). All optional; server tolerates missing.
	Result         *JobResult `json:"result,omitempty"`
	RepoSizeBytes  *uint64    `json:"repo_size_bytes,omitempty"` // sent only when server asks via reconcile_repo_stats
}

// JobResult is the per-run summary reported after a backup completes.
type JobResult struct {
	BytesTotal    uint64   `json:"bytes_total,omitempty"`
	BytesNew      uint64   `json:"bytes_new,omitempty"`
	FilesTotal    uint64   `json:"files_total,omitempty"`
	FilesNew      uint64   `json:"files_new,omitempty"`
	SnapshotID    string   `json:"snapshot_id,omitempty"`
	SnapshotCount uint32   `json:"snapshot_count,omitempty"` // restic-only; total snapshots in repo
	SnapshotIDs   []string `json:"snapshot_ids,omitempty"`   // restic-only; full set of snapshot IDs post-prune. Server diffs prev vs curr to flag specific disappearances. Cap 1000 client-side.
}

// JobDailyStats is an aggregate row for one (node, job, day).
type JobDailyStats struct {
	NodeID         uint64
	JobID          string
	Day            time.Time
	Runs           int
	Successes      int
	Warnings       int
	Failures       int
	Skipped        int
	TotalDurationS int64
	BytesNewSum    int64
	WorstErrorCat  string
}

// JobSilence represents an active mute on a (node, job).
// SilencedUntil == nil means "forever until explicitly cleared".
type JobSilence struct {
	NodeID        uint64
	JobID         string
	SilencedUntil *time.Time
	Reason        string
	CreatedBy     *uint64
	CreatedAt     time.Time
}

// IsActive returns true if the silence is still in effect.
func (s *JobSilence) IsActive() bool {
	if s == nil {
		return false
	}
	if s.SilencedUntil == nil {
		return true
	}
	return s.SilencedUntil.After(time.Now())
}

// JobTag is a label applied to jobs. Priority (0–3) influences alert weighting.
type JobTag struct {
	ID        uint64
	Name      string
	Color     string
	TextColor string
	Priority  uint8 // 0=low, 1=normal, 2=high, 3=critical
	CreatedAt time.Time
}

// ServerTuning holds global tunable settings (single-row table).
type ServerTuning struct {
	RepoStatsIntervalSeconds     uint32
	RepoStatsTimeoutSeconds      uint32
	RetentionRawDays             uint32
	RetentionPostRunDays         uint32
	OfflineThresholdMinutes      uint32
	OfflineCheckIntervalMinutes  uint32
	DefaultSilenceSeconds        uint32
	AnomalySnapshotDropThreshold uint32
	AnomalyFilesDropPct          uint32
	AnomalyFilesDropMin          uint32
	AnomalyBytesDropPct          uint32
	AnomalyBytesDropMinMB        uint32
	AnomalyAckRetentionDays        uint32
	AuditRetentionDays             uint32
	TerminalRecordingEnabled       bool
	TerminalRecordingRetentionDays uint32
	SilentAlertThresholdMinutes    uint32
	LatestCLIVersion               string
	LatestCLIVersionCheckedAt      *time.Time
	UpdateCheckIntervalMinutes     uint32
	LatestServerVersion            string
	LatestServerVersionCheckedAt   *time.Time
}

// AuditEvent is the wire format CLI nodes send inside the heartbeat payload.
type AuditEvent struct {
	Seq      uint64            `json:"seq"`
	TS       int64             `json:"ts"` // Unix seconds, UTC
	Category string            `json:"category"`
	Severity string            `json:"severity"` // info | warn | critical
	Actor    string            `json:"actor"`
	Message  string            `json:"message"`
	Details  map[string]string `json:"details,omitempty"`
	HMAC     string            `json:"hmac,omitempty"` // v2.5.0+: per-event HMAC chain signature
}

// AuditLog is a single row from the audit_log table, used for display + query.
type AuditLog struct {
	ID            uint64
	TS            time.Time
	Source        string // "server" | "node"
	SourceNodeID  *uint64
	SourceSeq     *uint64
	UserID        *uint64
	Username      string
	IP            string
	Category      string
	Severity      string
	Actor         string
	Action        string
	EntityType    string
	EntityID      string
	Message       string
	DetailsJSON   string
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

// UserTag represents a user-defined label that can be attached to users.
// Fully separate from node Tags — different catalog, different junction.
type UserTag struct {
	ID        uint64
	Name      string
	Color     string
	TextColor string
	CreatedAt time.Time
}

// AccessLevel represents the effective permission on a node.
// "none" means the user cannot see the node at all.
type AccessLevel string

const (
	AccessNone   AccessLevel = "none"
	AccessView   AccessLevel = "view"
	AccessManage AccessLevel = "manage"
)

// AtLeastView returns true if access is view or manage.
func (a AccessLevel) AtLeastView() bool   { return a == AccessView || a == AccessManage }
func (a AccessLevel) CanManage() bool     { return a == AccessManage }

// MaxAccess returns the higher of two access levels.
func MaxAccess(a, b AccessLevel) AccessLevel {
	order := map[AccessLevel]int{AccessNone: 0, AccessView: 1, AccessManage: 2}
	if order[a] >= order[b] {
		return a
	}
	return b
}

// CapByRole caps an access level according to the user's role.
// - superadmin: returns as-is (caller should bypass)
// - manager: can reach manage
// - user/guest: capped at view
func CapByRole(role string, access AccessLevel) AccessLevel {
	if role == "superadmin" || role == "manager" {
		return access
	}
	if access == AccessManage {
		return AccessView
	}
	return access
}

// Effect is allow (grant) or deny (block).
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// SubjectType / TargetType enumerate what a rule can reference.
type SubjectType string
type TargetType string

const (
	SubjectUser      SubjectType = "user"
	SubjectUserGroup SubjectType = "user_group"
	SubjectUserTag   SubjectType = "user_tag"

	TargetNode    TargetType = "node"
	TargetNodeTag TargetType = "node_tag"
)

// PermissionRule — unified rule with priority, effect, polymorphic subject and target.
type PermissionRule struct {
	ID                 uint64
	Priority           int
	Enabled            bool
	Effect             Effect
	Access             AccessLevel // "view" or "manage" (not "none")
	SubjectType        SubjectType
	SubjectID          uint64
	TargetType         TargetType
	TargetID           uint64
	LockedBySuperadmin bool
	CreatedBy          *uint64
	CreatedAt          time.Time
}

// UserGroup — a team of users scoped to a client.
type UserGroup struct {
	ID            uint64
	Name          string
	ClientGroupID uint64
	CreatedAt     time.Time
}

// UserGroupMember — membership, with optional lead flag.
type UserGroupMember struct {
	UserGroupID uint64
	UserID      uint64
	IsLead      bool
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
