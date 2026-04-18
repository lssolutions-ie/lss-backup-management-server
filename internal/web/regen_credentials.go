package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

// HandleRegenerateAllCredentials generates a new PSK, SSHes into the node to
// update config.toml with the new PSK, then runs --regenerate-credentials to
// create new SSH user/password and encryption password. The CLI sends the new
// creds back via the next heartbeat.
func (s *Server) HandleRegenerateAllCredentials(w http.ResponseWriter, r *http.Request) {
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
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.Unmarshal(body, &req)

	if req.Username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "ssh_creds_required"})
		return
	}

	lg := logx.FromContext(r.Context())
	lg.Warn("regenerate all credentials: starting", "node_id", node.ID, "node_name", node.Name)

	// Step 1: Generate new PSK
	psk, err := crypto.GeneratePSK()
	if err != nil {
		lg.Error("regen creds: generate PSK failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate PSK"})
		return
	}

	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		lg.Error("regen creds: encrypt PSK failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to encrypt PSK"})
		return
	}

	// Step 2: SSH into node and update config.toml with new PSK
	configDir := "/etc/lss-backup-cli"
	if node.HwOS == "windows" {
		configDir = `C:\ProgramData\LSS Backup`
	} else if node.HwOS == "darwin" {
		configDir = "/etc/lss-backup-cli"
	}

	var updatePSKCmd string
	if node.HwOS == "windows" {
		updatePSKCmd = fmt.Sprintf(`powershell -Command "(Get-Content '%s\config.toml') -replace 'psk_key = \".*\"', 'psk_key = \"%s\"' | Set-Content '%s\config.toml'"`,
			configDir, psk, configDir)
	} else {
		escapedPSK := strings.ReplaceAll(psk, `\`, `\\`)
		escapedPSK = strings.ReplaceAll(escapedPSK, `/`, `\/`)
		escapedPSK = strings.ReplaceAll(escapedPSK, `&`, `\&`)
		updatePSKCmd = fmt.Sprintf(`sed -i 's/psk_key = ".*"/psk_key = "%s"/' %s/config.toml`, escapedPSK, configDir)
	}

	output, err := sshExecOnNodeSudo(node, req.Username, req.Password, updatePSKCmd)
	if err != nil {
		lg.Error("regen creds: update config.toml failed", "err", err.Error(), "output", string(output))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update PSK on node: " + err.Error()})
		return
	}
	lg.Info("regen creds: PSK updated in config.toml", "node_id", node.ID)

	// Step 3: Update PSK in server DB
	if err := s.DB.UpdateNodePSK(node.ID, encrypted); err != nil {
		lg.Error("regen creds: update DB PSK failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save PSK in database"})
		return
	}

	// Step 4: Store new PSK in vault
	_ = s.DB.AutoStoreNodePSK(node.ID, psk, s.AppKey)

	// Step 5: Run --regenerate-credentials on the node
	cmd := fmt.Sprintf("%s --regenerate-credentials", cliPath(node.HwOS))
	output, err = sshExecOnNodeSudo(node, req.Username, req.Password, cmd)
	if err != nil {
		lg.Error("regen creds: regenerate-credentials failed", "err", err.Error(), "output", string(output))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "PSK updated but credential regeneration failed: " + err.Error(),
			"output": string(output),
		})
		return
	}

	lg.Info("regen creds: all credentials regenerated", "node_id", node.ID, "node_name", node.Name)

	s.auditServer(r, "all_credentials_regenerated", "critical", "regenerate", "node",
		fmt.Sprintf("%d", node.ID),
		"All credentials regenerated for node "+node.Name+" (PSK + SSH + encryption password)", nil)


	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ok":     "true",
		"output": string(output),
	})
}
