package main

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/api"
	"github.com/lssolutions-ie/lss-management-server/internal/config"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
	"github.com/lssolutions-ie/lss-management-server/internal/web"
	"github.com/lssolutions-ie/lss-management-server/internal/worker"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	logx.Init()

	configPath := os.Getenv("LSS_CONFIG")
	if configPath == "" {
		configPath = "config.toml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Load or generate app secret key
	appKey, err := loadOrCreateSecretKey(cfg.Security.SecretKeyFile)
	if err != nil {
		log.Fatalf("secret key: %v", err)
	}

	// Connect to database
	database, err := db.Open(cfg.Database.DSN)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close() //nolint:errcheck

	// Run migrations
	if err := database.RunMigrations("migrations"); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Clean up expired sessions
	if err := database.DeleteExpiredSessions(); err != nil {
		log.Printf("cleanup sessions: %v", err)
	}

	notifier := notify.NoOpNotifier{}

	// Start background workers
	offlineChecker := worker.NewOfflineChecker(database, notifier)
	offlineChecker.Start()
	silentChecker := worker.NewSilentNodeChecker(database)
	silentChecker.Start()
	hostAuditWorker := worker.NewHostAuditWorker(database)
	hostAuditWorker.Start()
	retentionWorker := worker.NewRetentionWorker(database, cfg.Terminal.SessionsDir)
	retentionWorker.Start()
	versionChecker := worker.NewVersionChecker(database)
	versionChecker.Start()
	serverBackupWorker := worker.NewServerBackupWorker(database, appKey, cfg.Database.DSN, cfg.Security.SecretKeyFile, configPath, cfg.Terminal.SessionsDir)
	serverBackupWorker.Start()

	web.ServerVersion = Version

	// Wire HTTP handlers
	webServer := &web.Server{
		DB:         database,
		Config:     cfg,
		AppKey:     appKey,
		ConfigPath: configPath,
	}

	// Path to the authorized_keys file consumed by sshd's AuthorizedKeysCommand
	// for the restricted tunnel user. Overridable via LSS_TUNNEL_AUTHKEYS_FILE.
	tunnelAuthKeysFile := os.Getenv("LSS_TUNNEL_AUTHKEYS_FILE")
	if tunnelAuthKeysFile == "" {
		tunnelAuthKeysFile = "/var/lib/lss-management/tunnel_authorized_keys"
	}

	apiHandler := &api.Handler{
		DB:                       database,
		AppKey:                   appKey,
		Notifier:                 notifier,
		TunnelAuthorizedKeysFile: tunnelAuthKeysFile,
	}

	// Rebuild the authorized_keys file from the DB on startup so that any
	// keys already stored are represented, even if the file was deleted.
	if err := database.WriteTunnelAuthorizedKeys(tunnelAuthKeysFile); err != nil {
		log.Printf("tunnel authorized_keys startup sync: %v", err)
	}

	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Node API
	mux.HandleFunc("/api/v1/status", apiHandler.HandleStatus)
	mux.HandleFunc("/api/v1/install/", apiHandler.HandleInstall)
	mux.HandleFunc("/api/v1/recover/", apiHandler.HandleRecover)

	// Auth
	mux.HandleFunc("/setup", webServer.HandleSetup)
	mux.HandleFunc("/login", webServer.HandleLogin)
	mux.HandleFunc("/login/2fa", webServer.HandleTOTPVerify)
	mux.HandleFunc("/logout", webServer.RequireAuth(webServer.HandleLogout))

	// 2FA setup/disable and forced password change (requires auth)
	mux.HandleFunc("/settings/2fa/setup", webServer.RequireAuth(webServer.HandleTOTPSetup))
	mux.HandleFunc("/settings/2fa/disable", webServer.RequireAuth(webServer.HandleTOTPDisable))
	mux.HandleFunc("/settings/force-password", webServer.RequireAuth(webServer.HandleForcePassword))
	mux.HandleFunc("/settings/smtp", webServer.RequireSuperAdmin(webServer.HandleSMTPSettings))
	mux.HandleFunc("/settings/smtp/test", webServer.RequireSuperAdmin(webServer.HandleSMTPTest))

	// Dashboard
	mux.HandleFunc("/", webServer.RequireAuth(webServer.HandleDashboard))

	// All Nodes page (exact match — must be before /nodes/ prefix)
	mux.HandleFunc("/nodes", webServer.RequireAuth(webServer.HandleNodesList))
	mux.HandleFunc("/nodes/bulk-update-cli", webServer.RequireManagerOrAbove(webServer.HandleBulkUpdateCLI))
	mux.HandleFunc("/nodes/bulk-enable-dr", webServer.RequireSuperAdmin(webServer.HandleBulkEnableDR))
	mux.HandleFunc("/nodes/bulk-dr-run-now", webServer.RequireSuperAdmin(webServer.HandleBulkDRRunNow))

	// Nodes
	mux.HandleFunc("/nodes/new", webServer.RequireAuth(webServer.HandleNodeNew))
	mux.HandleFunc("/nodes/generate-install-token", webServer.RequireManagerOrAbove(webServer.HandleGenerateInstallToken))
	mux.HandleFunc("/nodes/", webServer.RequireAuth(nodeRouter(webServer)))

	// Tags (node tags)
	mux.HandleFunc("/tags", webServer.RequireAuth(webServer.HandleTags))
	mux.HandleFunc("/tags/new", webServer.RequireManagerOrAbove(webServer.HandleTagCreate))
	mux.HandleFunc("/tags/bulk-delete", webServer.RequireManagerOrAbove(webServer.HandleTagBulkDelete))
	mux.HandleFunc("/tags/check-usage", webServer.RequireManagerOrAbove(webServer.HandleTagCheckUsage))
	mux.HandleFunc("/tags/", webServer.RequireManagerOrAbove(tagRouter(webServer)))

	// User Tags (separate catalog — superadmin only)
	mux.HandleFunc("/user-tags", webServer.RequireSuperAdmin(webServer.HandleUserTags))
	mux.HandleFunc("/user-tags/new", webServer.RequireSuperAdmin(webServer.HandleUserTagCreate))
	mux.HandleFunc("/user-tags/bulk-delete", webServer.RequireSuperAdmin(webServer.HandleUserTagBulkDelete))
	mux.HandleFunc("/user-tags/check-usage", webServer.RequireSuperAdmin(webServer.HandleUserTagCheckUsage))
	mux.HandleFunc("/user-tags/", webServer.RequireSuperAdmin(userTagRouter(webServer)))

	// Job Tags (priority labels — superadmin only)
	mux.HandleFunc("/job-tags", webServer.RequireSuperAdmin(webServer.HandleJobTags))
	mux.HandleFunc("/job-tags/new", webServer.RequireSuperAdmin(webServer.HandleJobTagCreate))
	mux.HandleFunc("/job-tags/", webServer.RequireSuperAdmin(jobTagRouter(webServer)))

	// Terminal WebSocket (separate from /nodes/ tree because it uses a different path style)
	mux.HandleFunc("/ws/terminal", webServer.RequireAuth(webServer.HandleTerminalWS))

	// SSH-over-WebSocket tunnel for nodes holding reverse-forward connections.
	// NOT session-gated — nodes authenticate via HMAC-PSK in HTTP headers.
	mux.HandleFunc("/ws/ssh-tunnel", webServer.HandleSSHTunnelWS)

	// Groups (manager+)
	mux.HandleFunc("/groups", webServer.RequireManagerOrAbove(webServer.HandleGroups))
	mux.HandleFunc("/groups/new", webServer.RequireManagerOrAbove(webServer.HandleGroupNew))
	mux.HandleFunc("/groups/", webServer.RequireManagerOrAbove(groupRouter(webServer)))

	// Users (manager+)
	mux.HandleFunc("/users", webServer.RequireManagerOrAbove(webServer.HandleUsers))
	mux.HandleFunc("/users/new", webServer.RequireManagerOrAbove(webServer.HandleUserNew))
	mux.HandleFunc("/users/", webServer.RequireManagerOrAbove(userRouter(webServer)))

	// Audit log — superadmin/manager only
	mux.HandleFunc("/audit", webServer.RequireManagerOrAbove(webServer.HandleAudit))
	mux.HandleFunc("/audit/session/", webServer.RequireSuperAdmin(webServer.HandleSessionReplay))

	// Anomalies global page + archive + per-row ack
	mux.HandleFunc("/anomalies", webServer.RequireAuth(webServer.HandleAnomalies))
	mux.HandleFunc("/anomalies/", webServer.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/anomalies/archive") {
			webServer.HandleAnomalies(w, r)
			return
		}
		if r.URL.Path == "/anomalies/bulk-ack" {
			webServer.HandleAnomalyBulkAck(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/diff") {
			webServer.HandleAnomalyDiff(w, r)
			return
		}
		webServer.HandleAnomalyAck(w, r)
	}))

	// Permissions (manager+ can edit unlocked rules; superadmin can lock)
	mux.HandleFunc("/permissions", webServer.RequireManagerOrAbove(webServer.HandlePermissions))
	mux.HandleFunc("/permissions/rule", webServer.RequireManagerOrAbove(webServer.HandlePermissionRuleSave))
	mux.HandleFunc("/permissions/rule/", webServer.RequireManagerOrAbove(permissionRuleRouter(webServer)))

	// User Groups (superadmin only)
	mux.HandleFunc("/user-groups", webServer.RequireSuperAdmin(webServer.HandleUserGroups))
	mux.HandleFunc("/user-groups/new", webServer.RequireSuperAdmin(webServer.HandleUserGroupNew))
	mux.HandleFunc("/user-groups/", webServer.RequireSuperAdmin(userGroupRouter(webServer)))

	// Settings
	mux.HandleFunc("/settings", webServer.RequireAuth(webServer.HandleSettings))
	mux.HandleFunc("/settings/tuning", webServer.RequireSuperAdmin(webServer.HandleServerTuning))
	mux.HandleFunc("/settings/intelligence", webServer.RequireSuperAdmin(webServer.HandleIntelligenceTuning))
	mux.HandleFunc("/settings/node-disaster-recovery", webServer.RequireSuperAdmin(webServer.HandleDRSettings))
	mux.HandleFunc("/settings/dr/save-s3", webServer.RequireSuperAdmin(webServer.HandleDRSaveS3))
	mux.HandleFunc("/settings/dr/save-server", webServer.RequireSuperAdmin(webServer.HandleDRSaveServer))
	mux.HandleFunc("/settings/dr/save-node", webServer.RequireSuperAdmin(webServer.HandleDRSaveNode))
	mux.HandleFunc("/settings/dr/server-snapshots", webServer.RequireSuperAdmin(webServer.HandleDRServerSnapshots))
	mux.HandleFunc("/settings/dr/server-restore", webServer.RequireSuperAdmin(webServer.HandleDRServerRestore))
	mux.HandleFunc("/settings/updates", webServer.RequireSuperAdmin(webServer.HandleUpdateSettings))
	mux.HandleFunc("/settings/updates/check-cli", webServer.RequireSuperAdmin(webServer.HandleCheckCLIVersion))
	mux.HandleFunc("/settings/updates/check-server", webServer.RequireSuperAdmin(webServer.HandleCheckServerVersion))
	mux.HandleFunc("/settings/updates/apply", webServer.RequireSuperAdmin(webServer.HandleServerUpdate))
	mux.HandleFunc("/settings/pending-nodes", webServer.RequireManagerOrAbove(webServer.HandlePendingNodes))
	mux.HandleFunc("/settings/pending-nodes/delete", webServer.RequireManagerOrAbove(webServer.HandleDeletePendingNode))
	mux.HandleFunc("/settings/backup", webServer.RequireSuperAdmin(webServer.HandleBackupPage))
	mux.HandleFunc("/settings/backup/download", webServer.RequireSuperAdmin(webServer.HandleBackupDownload))
	mux.HandleFunc("/settings/backup/restore", webServer.RequireSuperAdmin(webServer.HandleRestore))
	mux.HandleFunc("/vault", webServer.RequireManagerOrAbove(webServer.HandleVault))
	mux.HandleFunc("/vault/setup", webServer.RequireManagerOrAbove(webServer.HandleVaultSetup))
	mux.HandleFunc("/vault/unlock", webServer.RequireManagerOrAbove(webServer.HandleVaultUnlock))
	mux.HandleFunc("/vault/lock", webServer.RequireManagerOrAbove(webServer.HandleVaultLock))
	mux.HandleFunc("/vault/save", webServer.RequireManagerOrAbove(webServer.HandleVaultSave))
	mux.HandleFunc("/vault/reveal", webServer.RequireManagerOrAbove(webServer.HandleVaultReveal))
	mux.HandleFunc("/api/v1/nodes-list", webServer.RequireManagerOrAbove(webServer.HandleNodesListJSON))

	// Wrap mux with request-id/access-log, then security headers.
	handler := securityHeaders(webServer.RequestLog(mux))

	slog.Info("starting server",
		"version", Version,
		"listen", cfg.Server.ListenAddr,
		"tunnel_authkeys", tunnelAuthKeysFile)
	if err := http.ListenAndServe(cfg.Server.ListenAddr, handler); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// securityHeaders adds HSTS and other security headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// loadOrCreateSecretKey reads the secret key file. If it does not exist:
//   - LSS_ENV=production → log fatal
//   - otherwise (dev)    → generate, save, warn, continue
func loadOrCreateSecretKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) < 32 {
			return nil, errors.New("secret key file too short (need at least 32 bytes)")
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if os.Getenv("LSS_ENV") == "production" {
		return nil, errors.New("secret key file missing and LSS_ENV=production; refusing to generate")
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	log.Printf("WARNING: generated new secret key at %s (dev mode)", path)
	return key, nil
}

// nodeRouter dispatches /nodes/{id}, /nodes/{id}/edit, /nodes/{id}/delete,
// /nodes/{id}/regenerate-psk, /nodes/{id}/psk.
func nodeRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/nodes/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 1 || parts[1] == "" {
			s.HandleNodeDetail(w, r)
			return
		}
		// Per-job silence: /nodes/{id}/jobs/{jobID}/silence
		if strings.HasPrefix(parts[1], "jobs/") && strings.HasSuffix(parts[1], "/silence") {
			s.HandleJobSilence(w, r)
			return
		}
		// Per-job history: /nodes/{id}/jobs/{jobID}/history
		if strings.HasPrefix(parts[1], "jobs/") && strings.HasSuffix(parts[1], "/history") {
			s.HandleJobHistory(w, r)
			return
		}
		// Anomalies (Security tab) for the node.
		if parts[1] == "anomalies" {
			s.HandleNodeAnomalies(w, r)
			return
		}
		if parts[1] == "anomaly-counts" {
			s.HandleNodeAnomalyCounts(w, r)
			return
		}
		if parts[1] == "audit" {
			s.HandleNodeAudit(w, r)
			return
		}
		if parts[1] == "reset-audit-chain" {
			s.HandleResetAuditChain(w, r)
			return
		}
		// Graceful deletion flow: /nodes/{id}/delete/{action}
		if strings.HasPrefix(parts[1], "delete/") {
			action := strings.TrimPrefix(parts[1], "delete/")
			switch action {
			case "initiate":
				s.HandleInitiateNodeDeletion(w, r)
			case "report":
				s.HandleDownloadCredentialReport(w, r)
			case "confirm":
				s.HandleConfirmNodeDeletion(w, r)
			case "cancel":
				s.HandleCancelNodeDeletion(w, r)
			default:
				http.NotFound(w, r)
			}
			return
		}
		// DR actions: /nodes/{id}/dr/{action}
		if strings.HasPrefix(parts[1], "dr/") {
			action := strings.TrimPrefix(parts[1], "dr/")
			switch action {
			case "enable":
				s.HandleDRNodeAction(w, r, true)
			case "disable":
				s.HandleDRNodeAction(w, r, false)
			case "run-now":
				s.HandleDRRunNow(w, r)
			case "snapshots":
				s.HandleDRNodeSnapshots(w, r)
			case "restore-snapshot":
				s.HandleDRNodeRestore(w, r)
			default:
				http.NotFound(w, r)
			}
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleNodeEdit(w, r)
		case "delete":
			s.HandleNodeDelete(w, r)
		case "regenerate-psk":
			s.HandleNodeRegeneratePSK(w, r)
		case "generate-recovery-token":
			s.HandleGenerateRecoveryToken(w, r)
		case "psk":
			s.HandleNodePSK(w, r)
		case "update-cli":
			s.HandleScheduleCLIUpdate(w, r)
		case "terminal":
			s.HandleTerminalPage(w, r)
		case "tags":
			s.HandleNodeTags(w, r)
		case "repo":
			s.HandleRepoPage(w, r)
		case "repo/jobs":
			s.HandleRepoJobs(w, r)
		case "repo/snapshots":
			s.HandleRepoSnapshots(w, r)
		case "repo/browse":
			s.HandleRepoBrowse(w, r)
		case "repo/browse-rsync":
			s.HandleRepoBrowseRsync(w, r)
		case "repo/download":
			s.HandleRepoDownload(w, r)
		case "repo/download-rsync":
			s.HandleRepoDownloadRsync(w, r)
		case "repo/download-zip":
			s.HandleRepoDownloadZip(w, r)
		case "repo/download-rsync-zip":
			s.HandleRepoDownloadRsyncZip(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func permissionRuleRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/permissions/rule/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "toggle":
			s.HandlePermissionRuleToggle(w, r)
		case "delete":
			s.HandlePermissionRuleDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func jobTagRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/job-tags/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleJobTagEdit(w, r)
		case "delete":
			s.HandleJobTagDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func userGroupRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/user-groups/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleUserGroupEdit(w, r)
		case "delete":
			s.HandleUserGroupDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func userTagRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/user-tags/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleUserTagEdit(w, r)
		case "delete":
			s.HandleUserTagDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func tagRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/tags/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleTagEdit(w, r)
		case "delete":
			s.HandleTagDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func groupRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/groups/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 1 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleGroupEdit(w, r)
		case "delete":
			s.HandleGroupDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func userRouter(s *web.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/users/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 1 || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "edit":
			s.HandleUserEdit(w, r)
		case "delete":
			s.HandleUserDelete(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}
