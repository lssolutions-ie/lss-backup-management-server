package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// HandleSessionReplay serves the replay viewer page at /audit/session/{filename}
// and the raw .cast at /audit/session/{filename}.cast.
// Superadmin only.
func (s *Server) HandleSessionReplay(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/audit/session/")
	if rest == "" || strings.Contains(rest, "/") || strings.Contains(rest, "..") {
		http.NotFound(w, r)
		return
	}
	// Only the basename is valid; normalise and verify extension.
	base := filepath.Base(rest)
	serveRaw := false
	name := base
	if strings.HasSuffix(base, ".cast.raw") {
		serveRaw = true
		name = strings.TrimSuffix(base, ".raw")
	}
	if !strings.HasSuffix(name, ".cast") {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.Config.Terminal.SessionsDir, name)
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}

	if serveRaw {
		http.ServeFile(w, r, path)
		return
	}

	// Audit the replay itself — it's a sensitive action.
	s.auditServer(r, "session_replay", "warn", "replay", "terminal", name,
		"Replayed terminal session "+name, map[string]string{"session_file": path})

	s.render(w, r, http.StatusOK, "replay.html", replayPageData{
		PageData: s.newPageData(r),
		Filename: name,
	})
	_ = log.Default
}

type replayPageData struct {
	PageData
	Filename string
}
