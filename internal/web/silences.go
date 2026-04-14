package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// HandleJobSilence handles mute/unmute for a (node, job). POST only.
// Path: /nodes/{nodeID}/jobs/{jobID}/silence
// Form fields:
//   - action: "mute" | "unmute"
//   - duration_seconds: seconds to silence (0 = forever) — only read when action=mute
//   - reason: optional text
func (s *Server) HandleJobSilence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)

	// Parse path: /nodes/{nodeID}/jobs/{jobID}/silence
	rest := strings.TrimPrefix(r.URL.Path, "/nodes/")
	parts := strings.Split(rest, "/")
	if len(parts) < 4 || parts[1] != "jobs" || parts[3] != "silence" {
		http.NotFound(w, r)
		return
	}
	nodeID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	jobID := parts[2]

	// Require manage access on the node.
	if !s.EnforceNodeManage(w, r, nodeID) {
		return
	}

	action := r.FormValue("action")
	switch action {
	case "unmute":
		if err := s.DB.DeleteJobSilence(nodeID, jobID); err != nil {
			log.Printf("silence: delete: %v", err)
		}
	case "mute":
		dur, _ := strconv.ParseInt(r.FormValue("duration_seconds"), 10, 64)
		var until *time.Time
		if dur > 0 {
			t := time.Now().Add(time.Duration(dur) * time.Second)
			until = &t
		} // else: forever
		reason := r.FormValue("reason")
		if err := s.DB.SetJobSilence(nodeID, jobID, until, reason, user.ID); err != nil {
			log.Printf("silence: set: %v", err)
		}
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	// Redirect back to the referring node page.
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = fmt.Sprintf("/nodes/%d", nodeID)
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
