package web

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

// dsnParts holds parsed MySQL DSN components.
type dsnParts struct {
	User     string
	Password string
	Host     string
	Port     string
	DBName   string
}

// parseDSN parses a Go MySQL DSN of the form user:password@tcp(host:port)/dbname?params.
func parseDSN(dsn string) (*dsnParts, error) {
	re := regexp.MustCompile(`^([^:]+):([^@]*)@tcp\(([^:]+):(\d+)\)/([^?]+)`)
	m := re.FindStringSubmatch(dsn)
	if m == nil {
		return nil, fmt.Errorf("cannot parse DSN")
	}
	return &dsnParts{
		User:     m[1],
		Password: m[2],
		Host:     m[3],
		Port:     m[4],
		DBName:   m[5],
	}, nil
}

type backupPageData struct {
	PageData
	Error   string
	Success string
}

// HandleBackupPage renders the backup & restore settings page.
func (s *Server) HandleBackupPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "backup.html", backupPageData{
		PageData: s.newPageData(r),
	})
}

// HandleBackupDownload streams a zip backup of the entire server state.
func (s *Server) HandleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	lg := logx.FromContext(r.Context())

	dsn, err := parseDSN(s.Config.Database.DSN)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	// Run mysqldump to a temp file (avoid buffering the entire dump in memory).
	tmpDump, err := os.CreateTemp("", "lss-backup-dump-*.sql")
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	defer os.Remove(tmpDump.Name())
	defer tmpDump.Close()

	dumpCmd := exec.Command("mysqldump",
		"--single-transaction",
		"--routines",
		"--triggers",
		"--hex-blob",
		"--default-character-set=utf8mb4",
		"-u", dsn.User,
		"-p"+dsn.Password,
		"-h", dsn.Host,
		"-P", dsn.Port,
		dsn.DBName,
	)
	dumpCmd.Stdout = tmpDump
	dumpCmd.Stderr = io.Discard

	if err := dumpCmd.Run(); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, fmt.Errorf("mysqldump: %w", err), "Internal Server Error")
		return
	}
	tmpDump.Close()

	// Gather table list for metadata.
	rows, err := s.DB.RawQuery("SHOW TABLES")
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err == nil {
			tables = append(tables, t)
		}
	}
	rows.Close()

	hostname, _ := os.Hostname()
	now := time.Now().UTC()

	metadata := map[string]interface{}{
		"version":    ServerVersion,
		"created_at": now.Format(time.RFC3339),
		"hostname":   hostname,
		"tables":     tables,
	}
	metaJSON, _ := json.MarshalIndent(metadata, "", "  ")

	// Set response headers for zip download.
	filename := fmt.Sprintf("lss-backup-%s.zip", now.Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Helper: add a file from disk to the zip.
	addFile := func(zipPath, diskPath string) error {
		f, err := os.Open(diskPath)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipPath
		header.Method = zip.Deflate
		zf, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(zf, f)
		return err
	}

	// 1. dump.sql
	if err := addFile("dump.sql", tmpDump.Name()); err != nil {
		lg.Error("backup: add dump.sql", "err", err.Error())
		return
	}

	// 2. metadata.json
	mw, err := zw.Create("metadata.json")
	if err != nil {
		lg.Error("backup: create metadata.json", "err", err.Error())
		return
	}
	mw.Write(metaJSON)

	// 3. secret.key
	if err := addFile("secret.key", s.Config.Security.SecretKeyFile); err != nil {
		lg.Warn("backup: add secret.key", "err", err.Error())
		// Non-fatal — continue.
	}

	// 4. config.toml
	if s.ConfigPath != "" {
		if err := addFile("config.toml", s.ConfigPath); err != nil {
			lg.Warn("backup: add config.toml", "err", err.Error())
		}
	}

	// 5. Session recordings (.cast files).
	sessDir := s.Config.Terminal.SessionsDir
	if sessDir != "" {
		entries, err := os.ReadDir(sessDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".cast") {
					continue
				}
				diskPath := filepath.Join(sessDir, e.Name())
				if err := addFile("sessions/"+e.Name(), diskPath); err != nil {
					lg.Warn("backup: add session file", "file", e.Name(), "err", err.Error())
				}
			}
		}
	}

	s.auditServer(r, "backup_created", "warn", "backup", "system", "",
		"Full server backup downloaded", nil)

	lg.Info("backup download completed", "filename", filename)
}

// HandleRestore accepts a backup zip upload and restores the server state.
func (s *Server) HandleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	lg := logx.FromContext(r.Context())

	// Limit upload to 500 MB.
	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)

	file, _, err := r.FormFile("backup_file")
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "backup.html", backupPageData{
			PageData: s.newPageData(r),
			Error:    "Please select a backup zip file.",
		})
		return
	}
	defer file.Close()

	// Save upload to temp file so we can use zip.OpenReader on it.
	tmpFile, err := os.CreateTemp("", "lss-restore-*.zip")
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	defer os.Remove(tmpFile.Name())

	size, err := io.Copy(tmpFile, file)
	if err != nil {
		tmpFile.Close()
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	tmpFile.Close()

	// Open as zip.
	zr, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "backup.html", backupPageData{
			PageData: s.newPageData(r),
			Error:    "Invalid zip file.",
		})
		return
	}
	defer zr.Close()

	// Build a map of files in the zip.
	zipFiles := make(map[string]*zip.File)
	for _, f := range zr.File {
		zipFiles[f.Name] = f
	}

	// Validate required files.
	for _, required := range []string{"dump.sql", "secret.key", "metadata.json"} {
		if _, ok := zipFiles[required]; !ok {
			s.render(w, r, http.StatusBadRequest, "backup.html", backupPageData{
				PageData: s.newPageData(r),
				Error:    fmt.Sprintf("Invalid backup: missing %s", required),
			})
			return
		}
	}

	// Read metadata.
	var backupMeta struct {
		Version   string `json:"version"`
		CreatedAt string `json:"created_at"`
		Hostname  string `json:"hostname"`
	}
	if mf, err := zipFiles["metadata.json"].Open(); err == nil {
		json.NewDecoder(mf).Decode(&backupMeta)
		mf.Close()
	}
	lg.Info("restore: starting", "backup_version", backupMeta.Version, "backup_date", backupMeta.CreatedAt, "backup_size", size)

	dsn, err := parseDSN(s.Config.Database.DSN)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	// Extract dump.sql to temp file.
	dumpTmp, err := os.CreateTemp("", "lss-restore-dump-*.sql")
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	defer os.Remove(dumpTmp.Name())

	dumpZF, err := zipFiles["dump.sql"].Open()
	if err != nil {
		dumpTmp.Close()
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	io.Copy(dumpTmp, dumpZF)
	dumpZF.Close()
	dumpTmp.Close()

	// Import dump.sql via mysql command.
	importCmd := exec.Command("mysql",
		"-u", dsn.User,
		"-p"+dsn.Password,
		"-h", dsn.Host,
		"-P", dsn.Port,
		dsn.DBName,
	)
	dumpInput, err := os.Open(dumpTmp.Name())
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	importCmd.Stdin = dumpInput
	importCmd.Stderr = io.Discard

	if err := importCmd.Run(); err != nil {
		dumpInput.Close()
		s.Fail(w, r, http.StatusInternalServerError, fmt.Errorf("mysql import: %w", err), "Internal Server Error")
		return
	}
	dumpInput.Close()
	lg.Info("restore: database imported")

	// Copy secret.key.
	if err := extractZipFile(zipFiles["secret.key"], s.Config.Security.SecretKeyFile); err != nil {
		lg.Error("restore: copy secret.key", "err", err.Error())
	}

	// Copy session recordings.
	sessDir := s.Config.Terminal.SessionsDir
	if sessDir != "" {
		os.MkdirAll(sessDir, 0o755)
		for name, zf := range zipFiles {
			if strings.HasPrefix(name, "sessions/") && strings.HasSuffix(name, ".cast") {
				dest := filepath.Join(sessDir, filepath.Base(name))
				if err := extractZipFile(zf, dest); err != nil {
					lg.Warn("restore: copy session file", "file", name, "err", err.Error())
				}
			}
		}
	}

	// Delete all sessions (force re-login).
	s.DB.RawExec("DELETE FROM sessions")
	lg.Info("restore: sessions cleared")

	// Force password reset + clear 2FA on all superadmin users.
	s.DB.RawExec("UPDATE users SET force_setup = 1, totp_secret = '', totp_enabled = 0 WHERE role = 'superadmin'")
	lg.Info("restore: superadmin users flagged for password reset")

	// Insert audit log entry directly (sessions are wiped so auditServer won't have a user).
	backupDate := backupMeta.CreatedAt
	if backupDate == "" {
		backupDate = "unknown"
	}
	s.DB.RawExec(
		"INSERT INTO audit_log (ts, source, category, severity, actor, action, entity_type, message) VALUES (NOW(), 'server', 'system_restored', 'critical', 'system', 'restore', 'system', ?)",
		fmt.Sprintf("System restored from backup dated %s (version %s, host %s)", backupDate, backupMeta.Version, backupMeta.Hostname),
	)
	lg.Info("restore: completed successfully")

	setFlash(w, "System restored. Please log in and set a new password.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// extractZipFile extracts a single zip file entry to the given disk path.
func extractZipFile(zf *zip.File, dest string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}
