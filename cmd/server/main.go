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

	// Wire HTTP handlers
	webServer := &web.Server{
		DB:     database,
		Config: cfg,
		AppKey: appKey,
	}

	apiHandler := &api.Handler{
		DB:       database,
		AppKey:   appKey,
		Notifier: notifier,
	}

	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Node API
	mux.HandleFunc("/api/v1/status", apiHandler.HandleStatus)

	// Auth
	mux.HandleFunc("/setup", webServer.HandleSetup)
	mux.HandleFunc("/login", webServer.HandleLogin)
	mux.HandleFunc("/logout", webServer.HandleLogout)

	// Dashboard
	mux.HandleFunc("/", webServer.RequireAuth(webServer.HandleDashboard))

	// Nodes
	mux.HandleFunc("/nodes/new", webServer.RequireAuth(webServer.HandleNodeNew))
	mux.HandleFunc("/nodes/", webServer.RequireAuth(nodeRouter(webServer)))

	// Terminal WebSocket (separate from /nodes/ tree because it uses a different path style)
	mux.HandleFunc("/ws/terminal", webServer.RequireAuth(webServer.HandleTerminalWS))

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

	log.Printf("listening on %s", cfg.Server.ListenAddr)
	if err := http.ListenAndServe(cfg.Server.ListenAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
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
