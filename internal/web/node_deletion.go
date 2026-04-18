package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/crypto"
	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
	"github.com/lssolutions-ie/lss-backup-server/internal/models"
)

// HandleInitiateNodeDeletion starts the graceful deletion flow.
// POST /nodes/{id}/delete/initiate — superadmin only.
func (s *Server) HandleInitiateNodeDeletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.IsSuperAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Pending nodes (never checked in) can be deleted directly.
	if node.NeverSeen() {
		if err := s.DB.DeleteNode(node.ID); err != nil {
			logx.FromContext(r.Context()).Error("delete pending node failed", "err", err.Error())
			setFlash(w, "Could not delete node.")
			http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
			return
		}
		s.auditServer(r, "node_deleted", "critical", "delete", "node",
			strconv.FormatUint(node.ID, 10),
			"Deleted pending node "+node.Name,
			map[string]string{"name": node.Name, "uid": node.UID})
		setFlash(w, "Node deleted.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := s.DB.SetNodeDeletionPhase(node.ID, "export_pending"); err != nil {
		logx.FromContext(r.Context()).Error("set deletion phase failed", "err", err.Error())
		setFlash(w, "Could not initiate deletion.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	s.auditServer(r, "node_deletion_initiated", "critical", "update", "node",
		strconv.FormatUint(node.ID, 10),
		"Initiated graceful deletion for node "+node.Name,
		map[string]string{"name": node.Name, "uid": node.UID})

	setFlash(w, "Waiting for node to export secrets...")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// HandleDownloadCredentialReport serves the decrypted credential report as a .txt file.
// GET /nodes/{id}/delete/report — superadmin only.
func (s *Server) HandleDownloadCredentialReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.IsSuperAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	if node.DeletionPhase != "export_received" {
		setFlash(w, "Secrets not yet received from node.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	enc, err := s.DB.GetNodeSecretsExport(node.ID)
	if err != nil || enc == "" {
		setFlash(w, "No secrets data available.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	plaintext, err := crypto.DecryptPSK(enc, s.AppKey)
	if err != nil {
		logx.FromContext(r.Context()).Error("decrypt secrets failed", "node_id", node.ID, "err", err.Error())
		setFlash(w, "Could not decrypt secrets.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	// Parse as generic JSON
	var secrets map[string]interface{}
	if err := json.Unmarshal([]byte(plaintext), &secrets); err != nil {
		logx.FromContext(r.Context()).Error("parse secrets failed", "node_id", node.ID, "err", err.Error())
		setFlash(w, "Could not parse secrets data.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	report := generateCredentialReport(node, secrets)

	s.auditServer(r, "secrets_exported", "critical", "export", "node",
		strconv.FormatUint(node.ID, 10),
		"Downloaded credential report for node "+node.Name,
		map[string]string{"name": node.Name, "uid": node.UID})

	filename := fmt.Sprintf("node-creds-%s.txt", node.UID)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(report)) //nolint:errcheck
}

// HandleConfirmNodeDeletion transitions to uninstall_pending.
// POST /nodes/{id}/delete/confirm — superadmin only.
func (s *Server) HandleConfirmNodeDeletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.IsSuperAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if node.DeletionPhase != "export_received" {
		setFlash(w, "Cannot confirm deletion — secrets not received yet.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	retainData := r.FormValue("retain_data") == "on" || r.FormValue("retain_data") == "1"

	if err := s.DB.SetNodeDeletionRetainData(node.ID, retainData); err != nil {
		logx.FromContext(r.Context()).Error("set retain_data failed", "err", err.Error())
	}
	if err := s.DB.SetNodeDeletionPhase(node.ID, "uninstall_pending"); err != nil {
		logx.FromContext(r.Context()).Error("set deletion phase failed", "err", err.Error())
		setFlash(w, "Could not confirm deletion.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	s.auditServer(r, "node_deletion_confirmed", "critical", "update", "node",
		strconv.FormatUint(node.ID, 10),
		"Confirmed deletion for node "+node.Name+fmt.Sprintf(" (retain_data=%v)", retainData),
		map[string]string{"name": node.Name, "uid": node.UID, "retain_data": fmt.Sprintf("%v", retainData)})

	setFlash(w, "Uninstall command will be sent on the next heartbeat.")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// HandleCancelNodeDeletion cancels the graceful deletion flow.
// POST /nodes/{id}/delete/cancel — superadmin only.
func (s *Server) HandleCancelNodeDeletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.IsSuperAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := s.DB.SetNodeDeletionPhase(node.ID, ""); err != nil {
		logx.FromContext(r.Context()).Error("cancel deletion failed", "err", err.Error())
	}
	if err := s.DB.ClearNodeSecretsExport(node.ID); err != nil {
		logx.FromContext(r.Context()).Error("clear secrets failed", "err", err.Error())
	}

	s.auditServer(r, "node_deletion_cancelled", "info", "update", "node",
		strconv.FormatUint(node.ID, 10),
		"Cancelled deletion for node "+node.Name,
		map[string]string{"name": node.Name, "uid": node.UID})

	setFlash(w, "Deletion cancelled.")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// generateCredentialReport builds the human-readable .txt report.
func generateCredentialReport(node *models.Node, secrets map[string]interface{}) string {
	var b strings.Builder
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	b.WriteString("═══════════════════════════════════════════════════════════════\n")
	b.WriteString("  LSS Backup — Node Credential Report\n")
	b.WriteString(fmt.Sprintf("  Generated: %s\n", ts))
	b.WriteString(fmt.Sprintf("  Node: %s (%s)\n", node.UID, node.Name))
	if node.HwHostname != "" {
		b.WriteString(fmt.Sprintf("  Hostname: %s\n", node.HwHostname))
	}
	b.WriteString("═══════════════════════════════════════════════════════════════\n\n")
	b.WriteString("  IMPORTANT: Store this file securely. These credentials are\n")
	b.WriteString("  the ONLY way to access the backup data after node deletion.\n\n")

	// Jobs section
	if jobsRaw, ok := secrets["jobs"]; ok {
		if jobs, ok := jobsRaw.([]interface{}); ok {
			for _, jobRaw := range jobs {
				job, ok := jobRaw.(map[string]interface{})
				if !ok {
					continue
				}
				jobID := strVal(job, "job_id")
				jobName := strVal(job, "job_name")
				program := strVal(job, "program")
				destPath := strVal(job, "destination_path")

				b.WriteString("───────────────────────────────────────────────────────────────\n")
				if jobName != "" {
					b.WriteString(fmt.Sprintf("  Job: %s — %s\n", jobID, jobName))
				} else {
					b.WriteString(fmt.Sprintf("  Job: %s\n", jobID))
				}
				if program != "" {
					b.WriteString(fmt.Sprintf("  Engine: %s\n", program))
				}
				if destPath != "" {
					b.WriteString(fmt.Sprintf("  Destination: %s\n", destPath))
				}
				b.WriteString("───────────────────────────────────────────────────────────────\n")

				// Write all credential fields
				credFields := []struct{ key, label string }{
					{"restic_password", "Restic Password"},
					{"s3_endpoint", "S3 Endpoint"},
					{"s3_bucket", "S3 Bucket"},
					{"s3_region", "S3 Region"},
					{"aws_access_key_id", "AWS Access Key ID"},
					{"aws_secret_access_key", "AWS Secret Access Key"},
					{"b2_account_id", "B2 Account ID"},
					{"b2_account_key", "B2 Account Key"},
					{"azure_account_name", "Azure Account Name"},
					{"azure_account_key", "Azure Account Key"},
					{"gcs_project_id", "GCS Project ID"},
					{"sftp_host", "SFTP Host"},
					{"sftp_user", "SFTP User"},
					{"sftp_password", "SFTP Password"},
					{"sftp_key_path", "SFTP Key Path"},
					{"encryption_key", "Encryption Key"},
					{"rclone_remote", "Rclone Remote"},
				}

				for _, cf := range credFields {
					if v := strVal(job, cf.key); v != "" {
						b.WriteString(fmt.Sprintf("  %-24s %s\n", cf.label+":", v))
					}
				}

				// Restic access example
				resticPW := strVal(job, "restic_password")
				awsKey := strVal(job, "aws_access_key_id")
				awsSecret := strVal(job, "aws_secret_access_key")
				if resticPW != "" && destPath != "" {
					b.WriteString("\n  To access this data with plain restic:\n")
					b.WriteString(fmt.Sprintf("    export RESTIC_PASSWORD=%q\n", resticPW))
					if awsKey != "" {
						b.WriteString(fmt.Sprintf("    export AWS_ACCESS_KEY_ID=%q\n", awsKey))
					}
					if awsSecret != "" {
						b.WriteString(fmt.Sprintf("    export AWS_SECRET_ACCESS_KEY=%q\n", awsSecret))
					}
					b.WriteString(fmt.Sprintf("    restic -r %s snapshots\n", destPath))
				}
				b.WriteString("\n")
			}
		}
	}

	// DR backup section
	if drRaw, ok := secrets["dr_backup"]; ok {
		if dr, ok := drRaw.(map[string]interface{}); ok {
			b.WriteString("───────────────────────────────────────────────────────────────\n")
			b.WriteString("  Disaster Recovery Backup\n")
			b.WriteString("───────────────────────────────────────────────────────────────\n")

			drFields := []struct{ key, label string }{
				{"s3_endpoint", "S3 Endpoint"},
				{"s3_bucket", "S3 Bucket"},
				{"s3_region", "S3 Region"},
				{"aws_access_key_id", "AWS Access Key ID"},
				{"aws_secret_access_key", "AWS Secret Access Key"},
				{"restic_password", "Restic Password"},
				{"node_folder", "Node Folder"},
			}
			for _, cf := range drFields {
				if v := strVal(dr, cf.key); v != "" {
					b.WriteString(fmt.Sprintf("  %-24s %s\n", cf.label+":", v))
				}
			}
			b.WriteString("\n")
		}
	}

	// SSH credentials section
	sshUser := strVal(secrets, "ssh_user")
	sshPassword := strVal(secrets, "ssh_password")
	if sshUser != "" || sshPassword != "" {
		b.WriteString("───────────────────────────────────────────────────────────────\n")
		b.WriteString("  SSH Credentials\n")
		b.WriteString("───────────────────────────────────────────────────────────────\n")
		if sshUser != "" {
			b.WriteString(fmt.Sprintf("  %-24s %s\n", "SSH User:", sshUser))
		}
		if sshPassword != "" {
			b.WriteString(fmt.Sprintf("  %-24s %s\n", "SSH Password:", sshPassword))
		}
		b.WriteString("\n")
	}

	b.WriteString("═══════════════════════════════════════════════════════════════\n")
	b.WriteString("  END OF REPORT\n")
	b.WriteString("═══════════════════════════════════════════════════════════════\n")

	return b.String()
}

// strVal safely extracts a string from a map[string]interface{}.
func strVal(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}
