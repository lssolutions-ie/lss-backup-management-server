package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
)

// HandleScheduleCLIUpdate SSHes to the node via tunnel and runs the update immediately.
// POST /nodes/{id}/update-cli
// Accepts SSH credentials in the request body (same pattern as repo browser / "Show deleted files").
func (s *Server) HandleScheduleCLIUpdate(w http.ResponseWriter, r *http.Request) {
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
		json.NewEncoder(w).Encode(map[string]string{"error": "Node has no active tunnel"})
		return
	}

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "ssh_creds_required"})
		return
	}

	cmd := fmt.Sprintf("%s --update --non-interactive", cliPath(node.HwOS))
	output, err := sshExecOnNodeSudo(node, username, password, cmd)
	if err != nil {
		logx.FromContext(r.Context()).Error("cli update failed",
			"node_id", node.ID, "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "Update failed: " + err.Error(),
			"output": string(output),
		})
		return
	}

	s.auditServer(r, "cli_update_executed", "info", "update", "node",
		fmt.Sprintf("%d", node.ID),
		"Immediate CLI update executed on "+node.Name, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ok":     "true",
		"output": string(output),
	})
}
