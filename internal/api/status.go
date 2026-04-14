package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/classify"
	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
)

type Handler struct {
	DB                    *db.DB
	AppKey                []byte
	Notifier              notify.Notifier
	TunnelAuthorizedKeysFile string // path the server rewrites when a new tunnel key arrives
}

type statusRequest struct {
	V    string `json:"v"`
	UID  string `json:"uid"`
	Data string `json:"data"`
}

func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req statusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest)
		return
	}

	// 1. Look up node by UID
	node, err := h.DB.GetNodeByUID(req.UID)
	if err != nil {
		log.Printf("api: get node uid=%s: %v", req.UID, err)
		apiError(w, http.StatusInternalServerError)
		return
	}
	if node == nil {
		log.Printf("api: unknown uid %q (request rejected)", req.UID)
		apiError(w, http.StatusNotFound)
		return
	}

	// 2. Decrypt stored PSK
	psk, err := crypto.DecryptPSK(node.PSKEncrypted, h.AppKey)
	if err != nil {
		log.Printf("api: decrypt psk node=%d: %v", node.ID, err)
		apiError(w, http.StatusInternalServerError)
		return
	}

	// 3. Decrypt payload
	plaintext, err := crypto.DecryptNodePayload(req.Data, psk)
	if err != nil {
		log.Printf("api: decrypt payload node=%d: %v", node.ID, err)
		apiError(w, http.StatusBadRequest)
		return
	}

	// 4. Parse inner payload
	var status models.NodeStatus
	if err := json.Unmarshal(plaintext, &status); err != nil {
		log.Printf("api: parse payload node=%d: %v", node.ID, err)
		apiError(w, http.StatusBadRequest)
		return
	}
	// Accept v1 (original) and v2 (v2.2.0+ CLIs with JobResult). Unknown versions rejected.
	if status.PayloadVersion != "1" && status.PayloadVersion != "2" {
		log.Printf("api: unknown payload_version %q from node=%d", status.PayloadVersion, node.ID)
		apiError(w, http.StatusBadRequest)
		return
	}

	// Freshness window: reject reports older than 10 minutes (replay protection)
	// or more than 2 minutes in the future (severe clock skew on the node).
	// This assumes nodes keep their clocks reasonably in sync via NTP.
	const maxAge = 10 * time.Minute
	const maxFuture = 2 * time.Minute
	now := time.Now().UTC()
	age := now.Sub(status.ReportedAt)
	if age > maxAge {
		log.Printf("api: stale report rejected node=%d uid=%s reported_at=%s age=%s",
			node.ID, node.UID, status.ReportedAt.Format(time.RFC3339), age)
		apiError(w, http.StatusBadRequest)
		return
	}
	if age < -maxFuture {
		log.Printf("api: future-dated report rejected node=%d uid=%s reported_at=%s skew=%s",
			node.ID, node.UID, status.ReportedAt.Format(time.RFC3339), -age)
		apiError(w, http.StatusBadRequest)
		return
	}

	// Normalise report_type: empty/unknown values default to "post_run" for
	// backwards compatibility with nodes that pre-date the field.
	reportType := status.ReportType
	if reportType != "heartbeat" && reportType != "post_run" {
		reportType = "post_run"
	}

	log.Printf("api: %s from node=%d uid=%s jobs=%d", reportType, node.ID, node.UID, len(status.Jobs))

	// 5. Upsert job snapshots, detect anomalies, and remove stale jobs.
	tuning, _ := h.DB.GetServerTuning()
	reportedJobIDs := make([]string, 0, len(status.Jobs))
	for _, job := range status.Jobs {
		cat := classify.Classify(job.LastError)

		// Capture previous state BEFORE the upsert for delta comparison.
		prev, _ := h.DB.GetJobSnapshotPrev(node.ID, job.ID)

		if err := h.DB.UpsertJobSnapshotWithCategory(node.ID, job, cat); err != nil {
			log.Printf("api: upsert job %s node=%d: %v", job.ID, node.ID, err)
		}
		reportedJobIDs = append(reportedJobIDs, job.ID)

		// Anomaly detection — only if we have a previous snapshot to compare against
		// and the CLI provided fresh result data.
		if prev != nil && job.Result != nil && tuning != nil {
			detectAnomalies(h.DB, node.ID, job, prev, tuning)
		}
	}
	if deleted, err := h.DB.DeleteStaleJobSnapshots(node.ID, reportedJobIDs); err != nil {
		log.Printf("api: delete stale jobs node=%d: %v", node.ID, err)
	} else if deleted > 0 {
		log.Printf("api: removed %d stale jobs from node=%d", deleted, node.ID)
	}

	// 6. Insert node report
	if err := h.DB.InsertNodeReport(node.ID, status.ReportedAt, reportType, string(plaintext)); err != nil {
		log.Printf("api: insert report node=%d: %v", node.ID, err)
	}

	// 7. Update last_seen_at (and first_seen_at if first check-in)
	if err := h.DB.UpdateNodeSeen(node.ID, now, node.FirstSeenAt == nil); err != nil {
		log.Printf("api: update seen node=%d: %v", node.ID, err)
	}

	// 7b. If the node reported tunnel info, persist it. On a public key change,
	// regenerate the authorized_keys file that sshd reads via AuthorizedKeysCommand.
	if status.Tunnel != nil {
		changed, err := h.DB.UpdateNodeTunnel(node.ID, status.Tunnel.Port, status.Tunnel.PublicKey, status.Tunnel.Connected)
		if err != nil {
			log.Printf("api: update tunnel node=%d: %v", node.ID, err)
		} else if changed && h.TunnelAuthorizedKeysFile != "" {
			if err := h.DB.WriteTunnelAuthorizedKeys(h.TunnelAuthorizedKeysFile); err != nil {
				log.Printf("api: rewrite tunnel authorized_keys: %v", err)
			} else {
				log.Printf("api: tunnel key changed for node=%d; authorized_keys regenerated", node.ID)
			}
		}
	}

	// 7c. If the node reported hardware info, persist it.
	if status.Hardware != nil {
		if err := h.DB.UpdateNodeHardware(node.ID, status.Hardware); err != nil {
			log.Printf("api: update hardware node=%d: %v", node.ID, err)
		}
	}

	// 8. Notify on job failures
	for _, job := range status.Jobs {
		if job.LastStatus == "failure" {
			snap := models.JobSnapshot{
				NodeID:                 node.ID,
				JobID:                  job.ID,
				JobName:                job.Name,
				Program:                job.Program,
				Enabled:                job.Enabled,
				LastStatus:             job.LastStatus,
				LastRunAt:              job.LastRunAt,
				LastRunDurationSeconds: job.LastRunDurationSeconds,
				LastError:              job.LastError,
				NextRunAt:              job.NextRunAt,
				ScheduleDescription:    job.ScheduleDescription,
			}
			if err := h.Notifier.NotifyJobFailure(*node, snap); err != nil {
				log.Printf("api: notify failure job=%s node=%d: %v", job.ID, node.ID, err)
			}
		}
	}

	resp := map[string]any{"ok": true}

	// If the node reported a tunnel public key, confirm it's registered so the
	// client knows it's safe to start the SSH tunnel without an auth race.
	if status.Tunnel != nil && status.Tunnel.PublicKey != "" {
		resp["tunnel_key_registered"] = true
	}

	// On heartbeats: tell the CLI which jobs need fresh `restic stats` this cycle.
	// Global interval comes from server_tuning, with per-job override respected.
	if reportType == "heartbeat" {
		if tuning, err := h.DB.GetServerTuning(); err == nil && tuning.RepoStatsIntervalSeconds > 0 {
			if ids, err := h.DB.JobsNeedingRepoStats(node.ID, tuning.RepoStatsIntervalSeconds); err == nil && len(ids) > 0 {
				resp["reconcile_repo_stats"] = ids
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// detectAnomalies compares the incoming job state against the previous job_snapshots
// row and inserts job_anomalies rows when configured thresholds are breached.
func detectAnomalies(db *db.DB, nodeID uint64, job models.JobStatus, prev *models.JobSnapshot, tuning *models.ServerTuning) {
	if job.Result == nil {
		return
	}

	// Snapshot count drop. Only check if previous was non-zero (rsync stays at 0 forever).
	if prev.SnapshotCount > 0 {
		if uint32Diff := int64(prev.SnapshotCount) - int64(job.Result.SnapshotCount); uint32Diff > 0 && uint32Diff > int64(tuning.AnomalySnapshotDropThreshold) {
			a := &models.JobAnomaly{
				NodeID:      nodeID,
				JobID:       job.ID,
				AnomalyType: models.AnomalySnapshotDrop,
				PrevValue:   int64(prev.SnapshotCount),
				CurrValue:   int64(job.Result.SnapshotCount),
				DeltaValue:  -uint32Diff,
				DeltaPct:    pct(uint32Diff, int64(prev.SnapshotCount)),
				SnapshotID:  job.Result.SnapshotID,
			}
			if err := db.InsertJobAnomaly(a); err != nil {
				log.Printf("anomaly: insert snapshot_drop: %v", err)
			} else {
				log.Printf("anomaly: SNAPSHOT_DROP node=%d job=%s prev=%d curr=%d (delta=-%d)",
					nodeID, job.ID, prev.SnapshotCount, job.Result.SnapshotCount, uint32Diff)
			}
		}
	}

	// Files total drop. Don't gate on curr > 0 — a true wipe legitimately
	// reports zero (CLI omits the field via omitempty when value is 0).
	if prev.FilesTotal > 0 {
		if filesDiff := int64(prev.FilesTotal) - int64(job.Result.FilesTotal); filesDiff > 0 {
			pctDrop := pct(filesDiff, int64(prev.FilesTotal))
			if filesDiff >= int64(tuning.AnomalyFilesDropMin) && pctDrop >= float64(tuning.AnomalyFilesDropPct) {
				a := &models.JobAnomaly{
					NodeID:      nodeID,
					JobID:       job.ID,
					AnomalyType: models.AnomalyFilesDrop,
					PrevValue:   int64(prev.FilesTotal),
					CurrValue:   int64(job.Result.FilesTotal),
					DeltaValue:  -filesDiff,
					DeltaPct:    pctDrop,
					SnapshotID:  job.Result.SnapshotID,
				}
				if err := db.InsertJobAnomaly(a); err != nil {
					log.Printf("anomaly: insert files_drop: %v", err)
				} else {
					log.Printf("anomaly: FILES_DROP node=%d job=%s prev=%d curr=%d (delta=-%d, %.1f%%)",
						nodeID, job.ID, prev.FilesTotal, job.Result.FilesTotal, filesDiff, pctDrop)
				}
			}
		}
	}

	// Bytes total drop. Same — don't gate on curr > 0.
	if prev.BytesTotal > 0 {
		if bytesDiff := int64(prev.BytesTotal) - int64(job.Result.BytesTotal); bytesDiff > 0 {
			pctDrop := pct(bytesDiff, int64(prev.BytesTotal))
			minBytes := int64(tuning.AnomalyBytesDropMinMB) * 1024 * 1024
			if bytesDiff >= minBytes && pctDrop >= float64(tuning.AnomalyBytesDropPct) {
				a := &models.JobAnomaly{
					NodeID:      nodeID,
					JobID:       job.ID,
					AnomalyType: models.AnomalyBytesDrop,
					PrevValue:   int64(prev.BytesTotal),
					CurrValue:   int64(job.Result.BytesTotal),
					DeltaValue:  -bytesDiff,
					DeltaPct:    pctDrop,
					SnapshotID:  job.Result.SnapshotID,
				}
				if err := db.InsertJobAnomaly(a); err != nil {
					log.Printf("anomaly: insert bytes_drop: %v", err)
				} else {
					log.Printf("anomaly: BYTES_DROP node=%d job=%s prev=%d curr=%d (delta=-%d, %.1f%%)",
						nodeID, job.ID, prev.BytesTotal, job.Result.BytesTotal, bytesDiff, pctDrop)
				}
			}
		}
	}
}

func pct(part, whole int64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) * 100 / float64(whole)
}

func apiError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]bool{"ok": false}) //nolint:errcheck
}
