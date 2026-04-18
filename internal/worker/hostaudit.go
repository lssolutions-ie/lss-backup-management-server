package worker

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/db"
)

// HostAuditWorker polls the local systemd journal for events on units we care
// about (sshd, sudo, lss-backup-server.service) and writes them into audit_log
// with source='host'. Resumable via a persisted journal cursor so we never
// re-emit a row we've already seen.
//
// Why not journald-go bindings or a Go DBus client? Because shelling out to
// journalctl requires no extra dependencies, works on every distro that ships
// systemd, and the volume is tiny (handful of events per minute even on a
// busy host).
type HostAuditWorker struct {
	db       *db.DB
	interval time.Duration
}

func NewHostAuditWorker(d *db.DB) *HostAuditWorker {
	return &HostAuditWorker{db: d, interval: 30 * time.Second}
}

func (w *HostAuditWorker) Start() {
	go w.run()
}

func (w *HostAuditWorker) run() {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for range t.C {
		w.tick()
	}
}

// journalEntry is a subset of the fields journalctl --output=json emits.
type journalEntry struct {
	Cursor              string `json:"__CURSOR"`
	RealtimeTimestamp   string `json:"__REALTIME_TIMESTAMP"`
	Unit                string `json:"_SYSTEMD_UNIT"`
	SyslogIdentifier    string `json:"SYSLOG_IDENTIFIER"`
	Message             string `json:"MESSAGE"`
}

func (w *HostAuditWorker) tick() {
	cursor, err := w.db.GetHostAuditCursor()
	if err != nil {
		lg.Error("hostaudit: get cursor failed", "err", err.Error())
		return
	}

	// Use SYSLOG_IDENTIFIER instead of -u (unit name) for SSH — the identifier
	// is always "sshd" regardless of whether the unit is ssh.service, sshd.service,
	// or openssh-server.service. Eliminates "exit status 1" spam on Ubuntu versions
	// where the unit name doesn't match.
	// journalctl uses AND between different field types. Use "+" separator
	// to create OR groups: (sshd OR sudo) OR (lss-backup-server.service).
	args := []string{
		"--output=json",
		"--no-pager",
		"SYSLOG_IDENTIFIER=sshd",
		"SYSLOG_IDENTIFIER=sudo",
		"+",
		"_SYSTEMD_UNIT=lss-backup-server.service",
	}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "--since=1 minute ago")
	}

	cmd := exec.Command("journalctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return
	}

	var lastCursor string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e journalEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		cat, sev, actor, msg, details := classifyJournalEntry(e)
		if cat == "" {
			lastCursor = e.Cursor
			continue
		}
		if err := w.db.InsertHostAuditEvent(cat, sev, actor, msg, details); err != nil {
			lg.Error("hostaudit: insert failed", "category", cat, "err", err.Error())
			continue
		}
		lastCursor = e.Cursor
	}
	if lastCursor != "" {
		if err := w.db.SetHostAuditCursor(lastCursor); err != nil {
			lg.Error("hostaudit: cursor save failed", "err", err.Error())
		}
	}
}

// classifyJournalEntry maps a raw journal line to an audit category, severity,
// actor, message and structured details. Returns ("", ...) if the line is not
// audit-worthy and should be skipped (cursor still advances).
func classifyJournalEntry(e journalEntry) (cat, sev, actor, msg string, details map[string]string) {
	unit := strings.ToLower(e.Unit)
	if unit == "" {
		unit = strings.ToLower(e.SyslogIdentifier)
	}

	// sshd: login success / failure / disconnect
	if strings.Contains(unit, "ssh") {
		switch {
		case strings.HasPrefix(e.Message, "Accepted password for "),
			strings.HasPrefix(e.Message, "Accepted publickey for "),
			strings.HasPrefix(e.Message, "Accepted keyboard-interactive"):
			user, ip, method := parseSSHAccepted(e.Message)
			return "host_ssh_login", "info", "user:" + user, e.Message,
				map[string]string{"user": user, "ip": ip, "method": method}
		case strings.HasPrefix(e.Message, "Failed password for "),
			strings.HasPrefix(e.Message, "Invalid user "):
			user, ip := parseSSHFailed(e.Message)
			return "host_ssh_login_failed", "warn", "user:" + user, e.Message,
				map[string]string{"user": user, "ip": ip}
		}
	}

	// sudo: command invocation
	if unit == "sudo" || strings.HasPrefix(unit, "sudo") || e.SyslogIdentifier == "sudo" {
		if strings.Contains(e.Message, " ; COMMAND=") {
			user, command := parseSudoLine(e.Message)
			return "host_sudo", "warn", "user:" + user, e.Message,
				map[string]string{"user": user, "command": command}
		}
	}

	// lss-backup-server.service lifecycle
	if strings.Contains(unit, "lss-backup-server") {
		switch {
		case strings.Contains(e.Message, "Started lss-backup-server"):
			return "host_service_started", "info", "system", e.Message, nil
		case strings.Contains(e.Message, "Stopping lss-backup-server"),
			strings.Contains(e.Message, "Stopped lss-backup-server"):
			return "host_service_stopped", "warn", "system", e.Message, nil
		case strings.Contains(e.Message, "lss-backup-server.service: Failed"),
			strings.Contains(e.Message, "lss-backup-server.service: Main process exited"):
			return "host_service_failed", "critical", "system", e.Message, nil
		}
	}

	return "", "", "", "", nil
}

// parseSSHAccepted handles lines like:
//   Accepted password for root from 10.0.0.5 port 12345 ssh2
//   Accepted publickey for ladia from 192.168.1.10 port 56789 ssh2: RSA SHA256:...
func parseSSHAccepted(msg string) (user, ip, method string) {
	parts := strings.Fields(msg)
	if len(parts) < 6 {
		return "", "", ""
	}
	method = parts[1]   // password / publickey / keyboard-interactive
	user = parts[3]
	for i, p := range parts {
		if p == "from" && i+1 < len(parts) {
			ip = parts[i+1]
			break
		}
	}
	return
}

// parseSSHFailed handles lines like:
//   Failed password for root from 10.0.0.5 port 12345 ssh2
//   Failed password for invalid user bob from 10.0.0.5 port 12345 ssh2
//   Invalid user bob from 10.0.0.5 port 12345
func parseSSHFailed(msg string) (user, ip string) {
	parts := strings.Fields(msg)
	if strings.HasPrefix(msg, "Invalid user ") && len(parts) >= 5 {
		user = parts[2]
		for i, p := range parts {
			if p == "from" && i+1 < len(parts) {
				ip = parts[i+1]
				break
			}
		}
		return
	}
	if strings.HasPrefix(msg, "Failed password for ") && len(parts) >= 6 {
		// "Failed password for [invalid user ]<user> from <ip> ..."
		idx := 3
		if parts[3] == "invalid" && parts[4] == "user" && len(parts) >= 8 {
			idx = 5
		}
		user = parts[idx]
		for i, p := range parts {
			if p == "from" && i+1 < len(parts) {
				ip = parts[i+1]
				break
			}
		}
	}
	return
}

// parseSudoLine handles classic sudo log lines:
//   ladia : TTY=pts/0 ; PWD=/home/ladia ; USER=root ; COMMAND=/usr/bin/systemctl restart lss-backup-server
func parseSudoLine(msg string) (user, command string) {
	if i := strings.Index(msg, " : "); i > 0 {
		user = strings.TrimSpace(msg[:i])
	}
	if i := strings.Index(msg, "COMMAND="); i > 0 {
		command = strings.TrimSpace(msg[i+len("COMMAND="):])
	}
	return
}
