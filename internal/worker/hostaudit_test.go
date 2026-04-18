package worker

import "testing"

func TestClassifyJournalEntry_SSHAccepted(t *testing.T) {
	e := journalEntry{
		Unit:    "ssh.service",
		Message: "Accepted publickey for root from 10.0.0.5 port 12345 ssh2: RSA SHA256:abc",
	}
	cat, sev, actor, _, details := classifyJournalEntry(e)
	if cat != "host_ssh_login" {
		t.Fatalf("category = %q, want host_ssh_login", cat)
	}
	if sev != "info" {
		t.Errorf("severity = %q, want info", sev)
	}
	if actor != "user:root" {
		t.Errorf("actor = %q, want user:root", actor)
	}
	if details["user"] != "root" || details["ip"] != "10.0.0.5" || details["method"] != "publickey" {
		t.Errorf("details unexpected: %+v", details)
	}
}

func TestClassifyJournalEntry_SSHFailedInvalidUser(t *testing.T) {
	e := journalEntry{
		Unit:    "sshd.service",
		Message: "Failed password for invalid user bob from 10.0.0.99 port 22 ssh2",
	}
	cat, sev, actor, _, details := classifyJournalEntry(e)
	if cat != "host_ssh_login_failed" {
		t.Fatalf("category = %q, want host_ssh_login_failed", cat)
	}
	if sev != "warn" {
		t.Errorf("severity = %q, want warn", sev)
	}
	if actor != "user:bob" || details["user"] != "bob" || details["ip"] != "10.0.0.99" {
		t.Errorf("actor=%q details=%+v", actor, details)
	}
}

func TestClassifyJournalEntry_Sudo(t *testing.T) {
	e := journalEntry{
		Unit:             "",
		SyslogIdentifier: "sudo",
		Message:          "ladia : TTY=pts/0 ; PWD=/home/ladia ; USER=root ; COMMAND=/usr/bin/systemctl restart lss-backup-server",
	}
	cat, sev, actor, _, details := classifyJournalEntry(e)
	if cat != "host_sudo" {
		t.Fatalf("category = %q, want host_sudo", cat)
	}
	if sev != "warn" {
		t.Errorf("severity = %q, want warn", sev)
	}
	if actor != "user:ladia" {
		t.Errorf("actor = %q, want user:ladia", actor)
	}
	if details["user"] != "ladia" || details["command"] != "/usr/bin/systemctl restart lss-backup-server" {
		t.Errorf("details unexpected: %+v", details)
	}
}

func TestClassifyJournalEntry_ServiceLifecycle(t *testing.T) {
	cases := []struct {
		msg, wantCat, wantSev string
	}{
		{"Started lss-backup-server.service - LSS Management Server.", "host_service_started", "info"},
		{"Stopping lss-backup-server.service - LSS Management Server...", "host_service_stopped", "warn"},
		{"lss-backup-server.service: Failed with result 'exit-code'.", "host_service_failed", "critical"},
	}
	for _, tc := range cases {
		e := journalEntry{Unit: "lss-backup-server.service", Message: tc.msg}
		cat, sev, _, _, _ := classifyJournalEntry(e)
		if cat != tc.wantCat || sev != tc.wantSev {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", tc.msg, cat, sev, tc.wantCat, tc.wantSev)
		}
	}
}

func TestClassifyJournalEntry_IgnoresNoise(t *testing.T) {
	e := journalEntry{Unit: "ssh.service", Message: "pam_unix(sshd:session): session opened for user root"}
	cat, _, _, _, _ := classifyJournalEntry(e)
	if cat != "" {
		t.Fatalf("expected empty category for noise line, got %q", cat)
	}
}
