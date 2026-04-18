package worker

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/db"
	"github.com/lssolutions-ie/lss-backup-server/internal/models"
)

type ServerBackupWorker struct {
	db          *db.DB
	appKey      []byte
	dsn         string
	keyFile     string
	configFile  string
	sessionsDir string
}

func NewServerBackupWorker(d *db.DB, appKey []byte, dsn, keyFile, configFile, sessionsDir string) *ServerBackupWorker {
	return &ServerBackupWorker{
		db:          d,
		appKey:      appKey,
		dsn:         dsn,
		keyFile:     keyFile,
		configFile:  configFile,
		sessionsDir: sessionsDir,
	}
}

func (w *ServerBackupWorker) Start() {
	go w.run()
}

func (w *ServerBackupWorker) run() {
	time.Sleep(30 * time.Second)
	w.tick()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		w.tick()
	}
}

func (w *ServerBackupWorker) tick() {
	tuning, err := w.db.GetServerTuning()
	if err != nil {
		lg.Error("server backup: get tuning failed", "err", err.Error())
		return
	}
	if !tuning.ServerBackupEnabled {
		return
	}

	if tuning.ServerBackupLastAt != nil {
		nextRun := tuning.ServerBackupLastAt.Add(time.Duration(tuning.ServerBackupIntervalHours) * time.Hour)
		if time.Now().Before(nextRun) {
			return
		}
	}

	drCfg, err := w.db.GetDRConfig(w.appKey)
	if err != nil || drCfg == nil || drCfg.S3Endpoint == "" {
		lg.Warn("server backup: DR config not set, skipping")
		return
	}

	lg.Info("server backup: starting")
	if err := w.doBackup(drCfg); err != nil {
		lg.Error("server backup: failed", "err", err.Error())
		w.db.UpdateServerBackupStatus("failure", err.Error())
		w.db.InsertServerAuditLog(0, "system", "", "server_backup", "critical", "backup", "server", "", "Automatic server backup failed: "+err.Error(), nil)
		return
	}
	lg.Info("server backup: completed successfully")
	w.db.UpdateServerBackupStatus("success", "")
	w.db.InsertServerAuditLog(0, "system", "", "server_backup", "info", "backup", "server", "", "Automatic server backup completed successfully", nil)
}

type dsnParts struct {
	User, Password, Host, Port, DBName string
}

func parseDSN(dsn string) (*dsnParts, error) {
	re := regexp.MustCompile(`^([^:]+):([^@]*)@tcp\(([^:]+):(\d+)\)/([^?]+)`)
	m := re.FindStringSubmatch(dsn)
	if m == nil {
		return nil, fmt.Errorf("cannot parse DSN")
	}
	return &dsnParts{User: m[1], Password: m[2], Host: m[3], Port: m[4], DBName: m[5]}, nil
}

func (w *ServerBackupWorker) doBackup(drCfg *models.DRConfig) error {
	tmpDir, err := os.MkdirTemp("", "lss-server-backup-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dsn, err := parseDSN(w.dsn)
	if err != nil {
		return fmt.Errorf("parse DSN: %w", err)
	}

	dumpPath := filepath.Join(tmpDir, "dump.sql")
	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return fmt.Errorf("create dump file: %w", err)
	}
	dumpCmd := exec.Command("mysqldump",
		"--single-transaction", "--routines", "--triggers",
		"--hex-blob", "--default-character-set=utf8mb4",
		"-u", dsn.User, "-p"+dsn.Password,
		"-h", dsn.Host, "-P", dsn.Port,
		dsn.DBName,
	)
	dumpCmd.Stdout = dumpFile
	dumpCmd.Stderr = io.Discard
	if err := dumpCmd.Run(); err != nil {
		dumpFile.Close()
		return fmt.Errorf("mysqldump: %w", err)
	}
	dumpFile.Close()

	copyFile := func(src, dstName string) error {
		s, err := os.Open(src)
		if err != nil {
			return err
		}
		defer s.Close()
		d, err := os.Create(filepath.Join(tmpDir, dstName))
		if err != nil {
			return err
		}
		defer d.Close()
		_, err = io.Copy(d, s)
		return err
	}

	if err := copyFile(w.keyFile, "secret.key"); err != nil {
		return fmt.Errorf("copy secret.key: %w", err)
	}
	if err := copyFile(w.configFile, "config.toml"); err != nil {
		return fmt.Errorf("copy config.toml: %w", err)
	}

	sessDir := filepath.Join(tmpDir, "sessions")
	os.MkdirAll(sessDir, 0700)
	if entries, err := os.ReadDir(w.sessionsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".cast" {
				copyFile(filepath.Join(w.sessionsDir, e.Name()), filepath.Join("sessions", e.Name()))
			}
		}
	}

	repo := fmt.Sprintf("s3:%s/%s/lss-backup-server", drCfg.S3Endpoint, drCfg.S3Bucket)

	password := drCfg.ServerResticPassword
	if password == "" {
		password = drCfg.ResticPassword
	}
	env := []string{
		"RESTIC_REPOSITORY=" + repo,
		"RESTIC_PASSWORD=" + password,
		"AWS_ACCESS_KEY_ID=" + drCfg.S3AccessKey,
		"AWS_SECRET_ACCESS_KEY=" + drCfg.S3SecretKey,
	}
	if drCfg.S3Region != "" {
		env = append(env, "AWS_DEFAULT_REGION="+drCfg.S3Region)
	}

	resticBin := "/usr/bin/restic"
	if p, err := exec.LookPath("restic"); err == nil {
		resticBin = p
	}

	initCmd := exec.Command(resticBin, "init")
	initCmd.Env = append(os.Environ(), env...)
	initCmd.Run()

	backupCmd := exec.Command(resticBin, "backup", ".")
	backupCmd.Dir = tmpDir
	backupCmd.Env = append(os.Environ(), env...)
	out, err := backupCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic backup: %w — %s", err, string(out))
	}

	keepLast := fmt.Sprintf("%d", drCfg.ServerKeepLast)
	keepDaily := fmt.Sprintf("%d", drCfg.ServerKeepDaily)
	if drCfg.ServerKeepLast == 0 {
		keepLast = "7"
	}
	if drCfg.ServerKeepDaily == 0 {
		keepDaily = "30"
	}
	forgetCmd := exec.Command(resticBin, "forget", "--keep-last", keepLast, "--keep-daily", keepDaily, "--prune")
	forgetCmd.Env = append(os.Environ(), env...)
	forgetCmd.Run()

	return nil
}
