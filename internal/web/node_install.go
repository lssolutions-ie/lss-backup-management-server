package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// HandleGenerateInstallToken creates a pending node + one-time install token.
// POST /nodes/generate-install-token
// Returns JSON with the install one-liners for Unix and Windows.
func (s *Server) HandleGenerateInstallToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	rlg := logx.FromContext(r.Context())

	if !s.validateCSRF(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid CSRF token"}) //nolint:errcheck
		return
	}

	clientGroupIDStr := r.FormValue("client_group_id")
	if clientGroupIDStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Client group is required"}) //nolint:errcheck
		return
	}

	clientGroupID, err := strconv.ParseUint(clientGroupIDStr, 10, 64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid client group"}) //nolint:errcheck
		return
	}

	// Generate random UID: lss-<8 hex chars>
	uidBytes := make([]byte, 4)
	if _, err := rand.Read(uidBytes); err != nil {
		rlg.Error("generate uid failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}
	uid := fmt.Sprintf("lss-%s", hex.EncodeToString(uidBytes))

	// Generate PSK as hex-only (not full printable ASCII) so it's safe to embed
	// in a bash/powershell script without escaping issues. Full-ASCII PSKs from
	// crypto.GeneratePSK() contain ()$"\! which break shell embedding.
	pskBytes := make([]byte, 64) // 64 bytes = 128 hex chars
	if _, err := rand.Read(pskBytes); err != nil {
		rlg.Error("generate psk failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}
	psk := hex.EncodeToString(pskBytes)

	// Encrypt PSK for storage
	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		rlg.Error("encrypt psk failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}

	// Create pending node
	nodeID, err := s.DB.CreatePendingNode(uid, encrypted, clientGroupID)
	if err != nil {
		rlg.Error("create pending node failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not create node"}) //nolint:errcheck
		return
	}

	// Auto-store PSK in vault
	_ = s.DB.AutoStoreNodePSK(nodeID, psk, s.AppKey)

	// Generate random token: 32 bytes -> 64-char hex (install token)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		rlg.Error("generate token failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash token for storage
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Store with 24h expiry
	expiresAt := time.Now().Add(24 * time.Hour)
	user := r.Context().Value(ctxUser).(*models.User)
	if err := s.DB.CreateInstallToken(tokenHash, nodeID, expiresAt, user.ID); err != nil {
		rlg.Error("create install token failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not create token"}) //nolint:errcheck
		return
	}

	// Always use HTTPS — the install URL contains a token that grants PSK access.
	// Never serve over HTTP even if X-Forwarded-Proto says so (internal proxy hop).
	baseURL := fmt.Sprintf("https://%s", r.Host)
	installURL := fmt.Sprintf("%s/api/v1/install/%s", baseURL, token)

	unixCmd := fmt.Sprintf("curl -fsSL '%s' | bash", installURL)
	winCmd := fmt.Sprintf("irm '%s?os=windows' | iex", installURL)

	// Audit
	s.auditServer(r, "install_token_created", "info", "create", "node",
		strconv.FormatUint(nodeID, 10),
		"Generated install token for pending node "+uid,
		map[string]string{"uid": uid, "client_group_id": clientGroupIDStr})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"unix_command":    unixCmd,
		"windows_command": winCmd,
	})
}

// HandleGenerateRecoveryToken creates a one-time recovery token for an existing registered node.
// POST /nodes/{id}/generate-recovery-token
// Returns JSON with recovery one-liners for Unix and Windows.
func (s *Server) HandleGenerateRecoveryToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	rlg := logx.FromContext(r.Context())

	if !s.validateCSRF(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid CSRF token"}) //nolint:errcheck
		return
	}

	// Extract node from URL: /nodes/{id}/generate-recovery-token
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	// Must be a registered node (not pending)
	if node.FirstSeenAt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Cannot recover a pending node"}) //nolint:errcheck
		return
	}

	// Validate that the PSK can be decrypted (it will be served at the recover endpoint)
	if _, err := crypto.DecryptPSK(node.PSKEncrypted, s.AppKey); err != nil {
		rlg.Error("recovery token: decrypt psk failed", "node_id", node.ID, "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}

	// Generate random token: 32 bytes -> 64-char hex
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		rlg.Error("recovery token: generate token failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error"}) //nolint:errcheck
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash token for storage
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Store with 24h expiry, linked to the EXISTING node
	expiresAt := time.Now().Add(24 * time.Hour)
	user := r.Context().Value(ctxUser).(*models.User)
	if err := s.DB.CreateInstallToken(tokenHash, node.ID, expiresAt, user.ID); err != nil {
		rlg.Error("recovery token: create token failed", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not create token"}) //nolint:errcheck
		return
	}

	// Build recovery URL (always HTTPS)
	baseURL := fmt.Sprintf("https://%s", r.Host)
	recoverURL := fmt.Sprintf("%s/api/v1/recover/%s", baseURL, token)

	unixCmd := fmt.Sprintf("curl -fsSL '%s' | bash", recoverURL)
	winCmd := fmt.Sprintf("irm '%s?os=windows' | iex", recoverURL)

	// Audit
	s.auditServer(r, "recovery_token_created", "critical", "create", "node",
		strconv.FormatUint(node.ID, 10),
		"Generated recovery token for node "+node.UID+" ("+node.Name+")",
		map[string]string{"uid": node.UID, "node_name": node.Name})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"unix_command":    unixCmd,
		"windows_command": winCmd,
	})
}
