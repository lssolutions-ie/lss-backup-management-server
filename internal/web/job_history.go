package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type jobHistoryEntry struct {
	ReportedAt             string `json:"reported_at"`
	LastStatus             string `json:"last_status"`
	LastRunAt              string `json:"last_run_at,omitempty"`
	LastRunDurationSeconds int    `json:"last_run_duration_seconds"`
	LastError              string `json:"last_error,omitempty"`
	ErrorCategory          string `json:"error_category,omitempty"`
	BytesNew               uint64 `json:"bytes_new,omitempty"`
	FilesNew               uint64 `json:"files_new,omitempty"`
	SnapshotID             string `json:"snapshot_id,omitempty"`
}

// HandleJobHistory returns the last N post-run states for a specific job.
// GET /nodes/{id}/jobs/{jobID}/history?status=&from=&to=&q=&limit=10
func (s *Server) HandleJobHistory(w http.ResponseWriter, r *http.Request) {
	// Path: /nodes/{nodeID}/jobs/{jobID}/history
	rest := strings.TrimPrefix(r.URL.Path, "/nodes/")
	parts := strings.Split(rest, "/")
	if len(parts) < 4 || parts[1] != "jobs" || parts[3] != "history" {
		http.NotFound(w, r)
		return
	}
	nodeID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	jobID := parts[2]

	if !s.EnforceNodeView(w, r, nodeID) {
		return
	}

	q := r.URL.Query()
	status := q.Get("status") // optional filter
	from := q.Get("from")     // YYYY-MM-DD
	to := q.Get("to")         // YYYY-MM-DD
	search := strings.ToLower(q.Get("q"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	// Pull a generous pool: every post_run carries all jobs, so the same run
	// shows up in many reports. Dedup + filter happens post-parse.
	poolSize := limit * 50
	if poolSize < 200 {
		poolSize = 200
	}
	if poolSize > 2000 {
		poolSize = 2000
	}

	reports, err := s.DB.ListRecentPostRunReports(nodeID, from, to, poolSize)
	if err != nil {
		log.Printf("job history: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Reports contain every job on every post_run cycle, so the same job run
	// appears in many reports with identical last_run_at. Deduplicate by
	// last_run_at so we show one row per actual run.
	seenRuns := make(map[string]bool)
	out := make([]jobHistoryEntry, 0, limit)
	for _, rep := range reports {
		var payload models.NodeStatus
		if err := json.Unmarshal([]byte(rep.PayloadJSON), &payload); err != nil {
			continue
		}
		for _, j := range payload.Jobs {
			if j.ID != jobID {
				continue
			}
			// Skip never-run jobs and dup runs.
			if j.LastRunAt == nil {
				break
			}
			key := j.LastRunAt.UTC().Format(time.RFC3339Nano)
			if seenRuns[key] {
				break
			}
			if status != "" && j.LastStatus != status {
				break
			}
			if search != "" {
				hay := strings.ToLower(j.LastError + " " + j.Name)
				if !strings.Contains(hay, search) {
					break
				}
			}
			seenRuns[key] = true
			entry := jobHistoryEntry{
				ReportedAt:             rep.ReportedAt.UTC().Format("2006-01-02 15:04:05"),
				LastStatus:             j.LastStatus,
				LastRunAt:              j.LastRunAt.UTC().Format("2006-01-02 15:04:05"),
				LastRunDurationSeconds: j.LastRunDurationSeconds,
				LastError:              j.LastError,
			}
			if j.Result != nil {
				entry.BytesNew = j.Result.BytesNew
				entry.FilesNew = j.Result.FilesNew
				entry.SnapshotID = j.Result.SnapshotID
			}
			out = append(out, entry)
			break
		}
		if len(out) >= limit {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"entries": out})
}
