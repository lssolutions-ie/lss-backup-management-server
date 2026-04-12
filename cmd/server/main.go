package main

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/api"
	"github.com/lssolutions-ie/lss-management-server/internal/config"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
	"github.com/lssolutions-ie/lss-management-server/internal/web"
	"github.com/lssolutions-ie/lss-management-server/internal/worker"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("lss-mgmt: ")

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

	// Start background worker
	offlineChecker := worker.NewOfflineChecker(database, notifier)
	offlineChecker.Start()

	web.ServerVersion = Version

	// Wire HTTP handlers
	webServer := &web.Server{
		DB:     database,
		Config: cfg,
		AppKey: appKey,
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

	// Auth
	mux.HandleFunc("/setup", webServer.HandleSetup)
	mux.HandleFunc("/login", webServer.HandleLogin)
	mux.HandleFunc("/login/2fa", webServer.HandleTOTPVerify)
	mux.HandleFunc("/logout", webServer.HandleLogout)

	// 2FA setup/disable and forced password change (requires auth)
	mux.HandleFunc("/settings/2fa/setup", webServer.RequireAuth(webServer.HandleTOTPSetup))
	mux.HandleFunc("/settings/2fa/disable", webServer.RequireAuth(webServer.HandleTOTPDisable))
	mux.HandleFunc("/settings/force-password", webServer.RequireAuth(webServer.HandleForcePassword))
	mux.HandleFunc("/settings/smtp", webServer.RequireSuperAdmin(webServer.HandleSMTPSettings))
	mux.HandleFunc("/settings/smtp/test", webServer.RequireSuperAdmin(webServer.HandleSMTPTest))

	// Dashboard
	mux.HandleFunc("/", webServer.RequireAuth(webServer.HandleDashboard))

	// Nodes
	mux.HandleFunc("/nodes/new", webServer.RequireAuth(webServer.HandleNodeNew))
	mux.HandleFunc("/nodes/", webServer.RequireAuth(nodeRouter(webServer)))

	// Tags
	mux.HandleFunc("/tags", webServer.RequireAuth(webServer.HandleTags))
	mux.HandleFunc("/tags/new", webServer.RequireSuperAdmin(webServer.HandleTagCreate))
	mux.HandleFunc("/tags/", webServer.RequireSuperAdmin(tagRouter(webServer)))

	// Terminal WebSocket (separate from /nodes/ tree because it uses a different path style)
	mux.HandleFunc("/ws/terminal", webServer.RequireAuth(webServer.HandleTerminalWS))

	// SSH-over-WebSocket tunnel for nodes holding reverse-forward connections.
	// NOT session-gated — nodes authenticate via HMAC-PSK in HTTP headers.
	mux.HandleFunc("/ws/ssh-tunnel", webServer.HandleSSHTunnelWS)

	// Groups (superadmin only)
	mux.HandleFunc("/groups", webServer.RequireSuperAdmin(webServer.HandleGroups))
	mux.HandleFunc("/groups/new", webServer.RequireSuperAdmin(webServer.HandleGroupNew))
	mux.HandleFunc("/groups/", webServer.RequireSuperAdmin(groupRouter(webServer)))

	// Users (superadmin only)
	mux.HandleFunc("/users", webServer.RequireSuperAdmin(webServer.HandleUsers))
	mux.HandleFunc("/users/new", webServer.RequireSuperAdmin(webServer.HandleUserNew))
	mux.HandleFunc("/users/", webServer.RequireSuperAdmin(userRouter(webServer)))

	// Settings
	mux.HandleFunc("/settings", webServer.RequireAuth(webServer.HandleSettings))

	// Wrap mux with security headers.
	handler := securityHeaders(mux)

	log.Printf("starting server version=%s listen=%s tunnel_authkeys=%s",
		Version, cfg.Server.ListenAddr, tunnelAuthKeysFile)
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
		switch parts[1] {
		case "edit":
			s.HandleNodeEdit(w, r)
		case "delete":
			s.HandleNodeDelete(w, r)
		case "regenerate-psk":
			s.HandleNodeRegeneratePSK(w, r)
		case "psk":
			s.HandleNodePSK(w, r)
		case "terminal":
			s.HandleTerminalPage(w, r)
		case "tags":
			s.HandleNodeTags(w, r)
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
