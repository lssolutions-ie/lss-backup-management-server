package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/classify"
	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
)

var lg = logx.Component("api")

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

	rlg := logx.FromContext(r.Context())

	var req statusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest)
		return
	}

	// 1. Look up node by UID
	node, err := h.DB.GetNodeByUID(req.UID)
	if err != nil {
		rlg.Error("get node failed", "uid", req.UID, "err", err.Error())
		apiError(w, http.StatusInternalServerError)
		return
	}
	if node == nil {
		rlg.Warn("unknown uid rejected", "uid", req.UID)
		apiError(w, http.StatusNotFound)
		return
	}

	// 2. Decrypt stored PSK
	psk, err := crypto.DecryptPSK(node.PSKEncrypted, h.AppKey)
	if err != nil {
		rlg.Error("decrypt psk failed", "node_id", node.ID, "err", err.Error())
		apiError(w, http.StatusInternalServerError)
		return
	}

	// 3. Decrypt payload
	plaintext, err := crypto.DecryptNodePayload(req.Data, psk)
	if err != nil {
		rlg.Warn("decrypt payload failed", "node_id", node.ID, "err", err.Error())
		apiError(w, http.StatusBadRequest)
		return
	}

	// 4. Parse inner payload
	var status models.NodeStatus
	if err := json.Unmarshal(plaintext, &status); err != nil {
		rlg.Warn("parse payload failed", "node_id", node.ID, "err", err.Error())
		apiError(w, http.StatusBadRequest)
		return
	}
	// Accept v1 (original), v2 (v2.2.0+ CLIs with JobResult), v3 (v2.3.0+ with audit_events).
	if status.PayloadVersion != "1" && status.PayloadVersion != "2" && status.PayloadVersion != "3" {
		rlg.Warn("unknown payload_version", "payload_version", status.PayloadVersion, "node_id", node.ID)
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
		rlg.Warn("stale report rejected",
			"node_id", node.ID, "uid", node.UID,
			"reported_at", status.ReportedAt.Format(time.RFC3339), "age", age.String())
		apiError(w, http.StatusBadRequest)
		return
	}
	if age < -maxFuture {
		rlg.Warn("future-dated report rejected",
			"node_id", node.ID, "uid", node.UID,
			"reported_at", status.ReportedAt.Format(time.RFC3339), "skew", (-age).String())
		apiError(w, http.StatusBadRequest)
		return
	}

	// Normalise report_type: empty/unknown values default to "post_run" for
	// backwards compatibility with nodes that pre-date the field.
	reportType := status.ReportType
	if reportType != "heartbeat" && reportType != "post_run" {
		reportType = "post_run"
	}

	// Routine per-heartbeat line demoted to DEBUG so it doesn't drown the journal.
	// Override via LSS_LOG_LEVEL=debug when you actually need to see every ping.
	rlg.Debug("status report",
		"type", reportType, "node_id", node.ID, "uid", node.UID, "jobs", len(status.Jobs))

	// 5. Upsert job snapshots, detect anomalies, and remove stale jobs.
	tuning, _ := h.DB.GetServerTuning()
	reportedJobIDs := make([]string, 0, len(status.Jobs))
	for _, job := range status.Jobs {
		cat := classify.Classify(job.LastError)

		// Capture previous state BEFORE the upsert for delta comparison.
		prev, _ := h.DB.GetJobSnapshotPrev(node.ID, job.ID)

		if err := h.DB.UpsertJobSnapshotWithCategory(node.ID, job, cat); err != nil {
			rlg.Error("upsert job failed", "job_id", job.ID, "node_id", node.ID, "err", err.Error())
		}
		reportedJobIDs = append(reportedJobIDs, job.ID)

		// Anomaly detection — only if we have a previous snapshot to compare against
		// and the CLI provided fresh result data.
		if prev != nil && job.Result != nil && tuning != nil {
			detectAnomalies(h.DB, node.ID, job, prev, tuning)
		}
	}
	if deleted, err := h.DB.DeleteStaleJobSnapshots(node.ID, reportedJobIDs); err != nil {
		rlg.Error("delete stale jobs failed", "node_id", node.ID, "err", err.Error())
	} else if deleted > 0 {
		rlg.Info("removed stale jobs", "count", deleted, "node_id", node.ID)
	}

	// 6. Insert node report
	if err := h.DB.InsertNodeReport(node.ID, status.ReportedAt, reportType, string(plaintext)); err != nil {
		rlg.Error("insert report failed", "node_id", node.ID, "err", err.Error())
	}

	// 7. Update last_seen_at (and first_seen_at if first check-in)
	if err := h.DB.UpdateNodeSeen(node.ID, now, node.FirstSeenAt == nil); err != nil {
		rlg.Error("update seen failed", "node_id", node.ID, "err", err.Error())
	}

	// 7b. If the node reported tunnel info, persist it. On a public key change,
	// regenerate the authorized_keys file that sshd reads via AuthorizedKeysCommand.
	if status.Tunnel != nil {
		changed, err := h.DB.UpdateNodeTunnel(node.ID, status.Tunnel.Port, status.Tunnel.PublicKey, status.Tunnel.Connected)
		if err != nil {
			rlg.Error("update tunnel failed", "node_id", node.ID, "err", err.Error())
		} else if changed && h.TunnelAuthorizedKeysFile != "" {
			if err := h.DB.WriteTunnelAuthorizedKeys(h.TunnelAuthorizedKeysFile); err != nil {
				rlg.Error("rewrite tunnel authorized_keys failed", "err", err.Error())
			} else {
				rlg.Info("tunnel key changed; authorized_keys regenerated", "node_id", node.ID)
			}
		}
	}

	// 7c. If the node reported hardware info, persist it.
	if status.Hardware != nil {
		if err := h.DB.UpdateNodeHardware(node.ID, status.Hardware); err != nil {
			rlg.Error("update hardware failed", "node_id", node.ID, "err", err.Error())
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
				rlg.Error("notify failure failed", "job_id", job.ID, "node_id", node.ID, "err", err.Error())
			}
		}
	}

	resp := map[string]any{"ok": true}

	// If the node reported a tunnel public key, confirm it's registered so the
	// client knows it's safe to start the SSH tunnel without an auth race.
	if status.Tunnel != nil && status.Tunnel.PublicKey != "" {
		resp["tunnel_key_registered"] = true
	}

	// Ingest audit events (v3+ CLI). Dedup via UNIQUE (source_node_id, seq).
	if len(status.AuditEvents) > 0 {
		prevAck, _ := h.DB.GetNodeAuditAckSeq(node.ID)
		newAck, err := h.DB.InsertNodeAuditEvents(node.ID, prevAck, status.AuditEvents)
		if err != nil {
			rlg.Error("audit ingest failed", "node_id", node.ID, "err", err.Error())
		}
		resp["audit_ack_seq"] = newAck
	} else {
		// Always return current ack seq so CLI can reconcile if it lost local state.
		if ack, err := h.DB.GetNodeAuditAckSeq(node.ID); err == nil && ack > 0 {
			resp["audit_ack_seq"] = ack
		}
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

	prevSnapID := prev.SnapshotID
	currSnapID := job.Result.SnapshotID

	// Snapshot count drop. Only check if previous was non-zero (rsync stays at 0 forever).
	if prev.SnapshotCount > 0 {
		if uint32Diff := int64(prev.SnapshotCount) - int64(job.Result.SnapshotCount); uint32Diff > 0 && uint32Diff > int64(tuning.AnomalySnapshotDropThreshold) {
			a := &models.JobAnomaly{
				NodeID:         nodeID,
				JobID:          job.ID,
				AnomalyType:    models.AnomalySnapshotDrop,
				PrevValue:      int64(prev.SnapshotCount),
				CurrValue:      int64(job.Result.SnapshotCount),
				DeltaValue:     -uint32Diff,
				DeltaPct:       pct(uint32Diff, int64(prev.SnapshotCount)),
				SnapshotID:     currSnapID,
				PrevSnapshotID: prevSnapID,
				CurrSnapshotID: currSnapID,
			}
			if err := db.InsertJobAnomaly(a); err != nil {
				lg.Error("insert snapshot_drop anomaly failed", "err", err.Error())
			} else {
				lg.Warn("anomaly snapshot_drop",
					"node_id", nodeID, "job_id", job.ID,
					"prev", prev.SnapshotCount, "curr", job.Result.SnapshotCount, "delta", -uint32Diff)
			}
		}
	}

	// Snapshot ID set diff — catches single-snapshot `restic forget` inside
	// retention that the count-based detector misses (count stays at N when
	// one is deleted and the next backup creates one). Only runs when CLI
	// ships SnapshotIDs (v2.5.0+); until then both sets are nil → no-op.
	if len(prev.SnapshotIDs) > 0 && len(job.Result.SnapshotIDs) > 0 {
		disappeared := snapshotSetDiff(prev.SnapshotIDs, job.Result.SnapshotIDs)
		if len(disappeared) > 0 {
			a := &models.JobAnomaly{
				NodeID:         nodeID,
				JobID:          job.ID,
				AnomalyType:    models.AnomalySnapshotDrop,
				PrevValue:      int64(len(prev.SnapshotIDs)),
				CurrValue:      int64(len(job.Result.SnapshotIDs)),
				DeltaValue:     -int64(len(disappeared)),
				DeltaPct:       pct(int64(len(disappeared)), int64(len(prev.SnapshotIDs))),
				SnapshotID:     strings.Join(disappeared, ","),
				PrevSnapshotID: prevSnapID,
				CurrSnapshotID: currSnapID,
			}
			if err := db.InsertJobAnomaly(a); err != nil {
				lg.Error("insert snapshot_id_drop anomaly failed", "err", err.Error())
			} else {
				lg.Warn("anomaly snapshot_id_drop",
					"node_id", nodeID, "job_id", job.ID,
					"disappeared", strings.Join(disappeared, ","),
					"prev_set_size", len(prev.SnapshotIDs),
					"curr_set_size", len(job.Result.SnapshotIDs))
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
					NodeID:         nodeID,
					JobID:          job.ID,
					AnomalyType:    models.AnomalyFilesDrop,
					PrevValue:      int64(prev.FilesTotal),
					CurrValue:      int64(job.Result.FilesTotal),
					DeltaValue:     -filesDiff,
					DeltaPct:       pctDrop,
					SnapshotID:     currSnapID,
					PrevSnapshotID: prevSnapID,
					CurrSnapshotID: currSnapID,
				}
				if err := db.InsertJobAnomaly(a); err != nil {
					lg.Error("insert files_drop anomaly failed", "err", err.Error())
				} else {
					lg.Warn("anomaly files_drop",
						"node_id", nodeID, "job_id", job.ID,
						"prev", prev.FilesTotal, "curr", job.Result.FilesTotal,
						"delta", -filesDiff, "pct", pctDrop)
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
					NodeID:         nodeID,
					JobID:          job.ID,
					AnomalyType:    models.AnomalyBytesDrop,
					PrevValue:      int64(prev.BytesTotal),
					CurrValue:      int64(job.Result.BytesTotal),
					DeltaValue:     -bytesDiff,
					DeltaPct:       pctDrop,
					SnapshotID:     currSnapID,
					PrevSnapshotID: prevSnapID,
					CurrSnapshotID: currSnapID,
				}
				if err := db.InsertJobAnomaly(a); err != nil {
					lg.Error("insert bytes_drop anomaly failed", "err", err.Error())
				} else {
					lg.Warn("anomaly bytes_drop",
						"node_id", nodeID, "job_id", job.ID,
						"prev", prev.BytesTotal, "curr", job.Result.BytesTotal,
						"delta", -bytesDiff, "pct", pctDrop)
				}
			}
		}
	}
}

// snapshotSetDiff returns IDs present in prev but absent from curr.
func snapshotSetDiff(prev, curr []string) []string {
	currSet := make(map[string]struct{}, len(curr))
	for _, id := range curr {
		currSet[id] = struct{}{}
	}
	var disappeared []string
	for _, id := range prev {
		if _, ok := currSet[id]; !ok {
			disappeared = append(disappeared, id)
		}
	}
	return disappeared
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
