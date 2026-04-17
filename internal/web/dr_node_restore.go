package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

// HandleDRNodeSnapshots lists restic snapshots for a specific node's DR repo.
func (s *Server) HandleDRNodeSnapshots(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	drCfg, err := s.DB.GetDRConfig(s.AppKey)
	if err != nil || drCfg == nil || drCfg.S3Endpoint == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "DR S3 config not set"})
		return
	}
	if drCfg.ResticPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Node restic password not configured"})
		return
	}

	repo := fmt.Sprintf("s3:%s/%s/client-nodes/%s/%s", drCfg.S3Endpoint, drCfg.S3Bucket, node.ClientGroup, node.UID)

	resticBin := "/usr/bin/restic"
	if p, err := exec.LookPath("restic"); err == nil {
		resticBin = p
	}

	env := append(os.Environ(),
		"RESTIC_REPOSITORY="+repo,
		"RESTIC_PASSWORD="+drCfg.ResticPassword,
		"AWS_ACCESS_KEY_ID="+drCfg.S3AccessKey,
		"AWS_SECRET_ACCESS_KEY="+drCfg.S3SecretKey,
	)
	if drCfg.S3Region != "" {
		env = append(env, "AWS_DEFAULT_REGION="+drCfg.S3Region)
	}

	cmd := exec.Command(resticBin, "snapshots", "--json")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to list snapshots: " + err.Error()})
		return
	}

	var snapshots []resticSnapshot
	json.Unmarshal(out, &snapshots)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"snapshots": snapshots})
}

// HandleDRNodeRestore restores a node's config from a specific DR snapshot via SSH.
func (s *Server) HandleDRNodeRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}

	if !node.TunnelReady() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Node tunnel not connected"})
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req struct {
		SnapshotID string `json:"snapshot_id"`
		Username   string `json:"username"`
		Password   string `json:"password"`
	}
	json.Unmarshal(body, &req)

	if req.Username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "ssh_creds_required"})
		return
	}
	if req.SnapshotID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No snapshot ID provided"})
		return
	}

	lg := logx.FromContext(r.Context())
	lg.Warn("node DR restore: starting", "node_id", node.ID, "snapshot_id", req.SnapshotID)

	snapshotID := strings.ReplaceAll(req.SnapshotID, "'", "")
	snapshotID = strings.ReplaceAll(snapshotID, "\"", "")
	snapshotID = strings.ReplaceAll(snapshotID, ";", "")

	// Run restore detached via nohup+bash so it survives the tunnel drop
	// when the daemon stops. The CLI will restart the daemon at the end,
	// which re-establishes the tunnel.
	logFile := "/tmp/lss-dr-restore.log"
	cmd := fmt.Sprintf("nohup %s --dr-restore --snapshot %s > %s 2>&1 & echo $!", cliPath(node.HwOS), snapshotID, logFile)
	output, err := sshExecOnNodeSudo(node, req.Username, req.Password, cmd)
	if err != nil {
		lg.Error("node DR restore: failed to launch", "node_id", node.ID, "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "Restore failed: " + err.Error(),
			"output": string(output),
		})
		return
	}

	s.auditServer(r, "dr_node_restore", "critical", "restore", "node", fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("DR restore from snapshot %s initiated on node %s", req.SnapshotID, node.Name), nil)

	lg.Info("node DR restore: launched", "node_id", node.ID, "snapshot_id", req.SnapshotID, "pid", strings.TrimSpace(string(output)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ok":      "true",
		"message": "Restore initiated. The node will restart its daemon when complete. Check node status in a few minutes.",
	})
}
