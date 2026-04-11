package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"github.com/lssolutions-ie/lss-management-server/internal/notify"
)

type Handler struct {
	DB       *db.DB
	AppKey   []byte
	Notifier notify.Notifier
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
	if status.PayloadVersion != "1" {
		apiError(w, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	// 5. Upsert job snapshots
	for _, job := range status.Jobs {
		if err := h.DB.UpsertJobSnapshot(node.ID, job); err != nil {
			log.Printf("api: upsert job %s node=%d: %v", job.ID, node.ID, err)
		}
	}

	// 6. Insert node report
	if err := h.DB.InsertNodeReport(node.ID, status.ReportedAt, string(plaintext)); err != nil {
		log.Printf("api: insert report node=%d: %v", node.ID, err)
	}

	// 7. Update last_seen_at (and first_seen_at if first check-in)
	if err := h.DB.UpdateNodeSeen(node.ID, now, node.FirstSeenAt == nil); err != nil {
		log.Printf("api: update seen node=%d: %v", node.ID, err)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

func apiError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]bool{"ok": false}) //nolint:errcheck
}
