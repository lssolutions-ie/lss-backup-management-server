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
	ReportedAt             string   `json:"reported_at"`
	LastStatus             string   `json:"last_status"`
	LastRunAt              string   `json:"last_run_at,omitempty"`
	LastRunDurationSeconds int      `json:"last_run_duration_seconds"`
	LastError              string   `json:"last_error,omitempty"`
	ErrorCategory          string   `json:"error_category,omitempty"`
	BytesNew               uint64   `json:"bytes_new,omitempty"`
	FilesNew               uint64   `json:"files_new,omitempty"`
	BytesLost              uint64   `json:"bytes_lost,omitempty"` // populated when this run triggered a bytes_drop anomaly
	FilesLost              uint64   `json:"files_lost,omitempty"` // populated when this run triggered a files_drop anomaly
	SnapshotID             string   `json:"snapshot_id,omitempty"`
	Anomalies              []string `json:"anomalies,omitempty"` // anomaly types that fired for this run (for back-compat badges)
	AnomalyRows            []historyAnomaly `json:"anomaly_rows,omitempty"` // ids + ack state, for clickable ack buttons
}

type historyAnomaly struct {
	ID           uint64 `json:"id"`
	Type         string `json:"type"`
	Acknowledged bool   `json:"acknowledged"`
}

// HandleJobHistory returns the last N post-run states for a specific job.
// GET /nodes/{id}/jobs/{jobID}/history?status=&from=&to=&limit=10
func (s *Server) HandleJobHistory(w http.ResponseWriter, r *http.Request) {
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
	status := q.Get("status")
	from := q.Get("from")
	to := q.Get("to")
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 10
	}

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

	// Build a map of snapshot_id → anomaly objects so we can mark each row + show deltas.
	anomalies, _ := s.DB.ListJobAnomalies(nodeID, jobID, false, 500)
	anomaliesBySnap := make(map[string][]*models.JobAnomaly)
	for _, a := range anomalies {
		if a.SnapshotID == "" {
			continue
		}
		anomaliesBySnap[a.SnapshotID] = append(anomaliesBySnap[a.SnapshotID], a)
	}

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
			if j.LastRunAt == nil {
				break
			}
			key := j.LastRunAt.UTC().Format(time.RFC3339Nano)
			if seenRuns[key] {
				break
			}
			// Status filter — "suspicious" is a virtual status (real status=success but anomalies fired).
			if status != "" {
				if status == "suspicious" {
					if j.LastStatus != "success" {
						break
					}
					sid := ""
					if j.Result != nil {
						sid = j.Result.SnapshotID
					}
					if _, hasAnom := anomaliesBySnap[sid]; !hasAnom {
						break
					}
				} else if j.LastStatus != status {
					break
				}
			}
			seenRuns[key] = true
			entry := jobHistoryEntry{
				ReportedAt:             rep.ReportedAt.Format("02-01-2006 15:04:05"),
				LastStatus:             j.LastStatus,
				LastRunAt:              j.LastRunAt.Format("02-01-2006 15:04:05"),
				LastRunDurationSeconds: j.LastRunDurationSeconds,
				LastError:              j.LastError,
			}
			if j.Result != nil {
				entry.BytesNew = j.Result.BytesNew
				entry.FilesNew = j.Result.FilesNew
				entry.SnapshotID = j.Result.SnapshotID
				if anoms, ok := anomaliesBySnap[j.Result.SnapshotID]; ok {
					for _, a := range anoms {
						entry.Anomalies = append(entry.Anomalies, string(a.AnomalyType))
						entry.AnomalyRows = append(entry.AnomalyRows, historyAnomaly{
							ID:           a.ID,
							Type:         string(a.AnomalyType),
							Acknowledged: a.Acknowledged,
						})
						switch a.AnomalyType {
						case models.AnomalyBytesDrop:
							if a.DeltaValue < 0 {
								entry.BytesLost = uint64(-a.DeltaValue)
							}
						case models.AnomalyFilesDrop:
							if a.DeltaValue < 0 {
								entry.FilesLost = uint64(-a.DeltaValue)
							}
						}
					}
				}
			}
			out = append(out, entry)
			break
		}
		if len(out) >= limit {
			break
		}
	}

	log.Printf("job history: node=%d job=%s returned %d entries (status=%q from=%q to=%q limit=%d)", nodeID, jobID, len(out), status, from, to, limit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"entries": out})
}
