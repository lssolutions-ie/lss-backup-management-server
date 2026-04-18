package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/lssolutions-ie/lss-backup-server/internal/crypto"
	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
)

// vaultPasswordCache stores vault passwords in memory per session. Never persisted.
var vaultPasswordCache = struct {
	sync.Mutex
	passwords map[string]string // session token → vault password
}{passwords: make(map[string]string)}

func cacheVaultPassword(sessionToken, password string) {
	vaultPasswordCache.Lock()
	defer vaultPasswordCache.Unlock()
	vaultPasswordCache.passwords[sessionToken] = password
}

func getCachedVaultPassword(sessionToken string) string {
	vaultPasswordCache.Lock()
	defer vaultPasswordCache.Unlock()
	return vaultPasswordCache.passwords[sessionToken]
}

func clearVaultPassword(sessionToken string) {
	vaultPasswordCache.Lock()
	defer vaultPasswordCache.Unlock()
	delete(vaultPasswordCache.passwords, sessionToken)
}

type vaultPageData struct {
	PageData
	VaultSetUp bool
	Unlocked   bool
	Nodes      []vaultNodeData
}

type vaultNodeData struct {
	NodeID      uint64
	NodeName    string
	NodeUID     string
	ClientGroup string
	Entries     map[string]string // entry_type → decrypted value
}

var vaultEntryTypes = []string{"psk", "ssh_username", "ssh_password", "cli_encrypt_password"}

var vaultEntryLabels = map[string]string{
	"psk":                  "Pre-Shared Key",
	"ssh_username":         "SSH Username",
	"ssh_password":         "SSH Password",
	"cli_encrypt_password": "CLI Encryption Password",
}

// HandleVault renders the vault page.
func (s *Server) HandleVault(w http.ResponseWriter, r *http.Request) {
	vaultSetUp, _ := s.DB.VaultIsSetUp()
	sessionToken, _ := r.Context().Value(ctxSession).(string)
	vaultPW := getCachedVaultPassword(sessionToken)
	unlocked := vaultSetUp && vaultPW != ""

	pd := vaultPageData{
		PageData:   s.newPageData(r),
		VaultSetUp: vaultSetUp,
		Unlocked:   unlocked,
	}

	if unlocked {
		nodes, err := s.DB.ListNodesWithStatus(nil)
		if err == nil {
			for _, n := range nodes {
				entries, err := s.DB.GetVaultEntries(n.ID)
				if err != nil {
					entries = nil
				}
				nd := vaultNodeData{
					NodeID:      n.ID,
					NodeName:    n.Name,
					NodeUID:     n.UID,
					ClientGroup: n.ClientGroup,
					Entries:     make(map[string]string),
				}
				for _, e := range entries {
					plain, err := crypto.VaultDecrypt(e.ValueEnc, s.AppKey)
					if err == nil {
						nd.Entries[e.EntryType] = plain
					}
				}
				pd.Nodes = append(pd.Nodes, nd)
			}
		}
	}

	s.render(w, r, http.StatusOK, "vault.html", pd)
}

// HandleVaultSetup creates the vault with the initial password.
func (s *Server) HandleVaultSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	password := r.FormValue("vault_password")
	confirm := r.FormValue("vault_password_confirm")

	if len(password) < 64 {
		setFlash(w, "Vault password must be at least 64 characters.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}
	if password != confirm {
		setFlash(w, "Passwords do not match.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}

	sentinel, err := crypto.VaultCreateSentinel(password, s.AppKey)
	if err != nil {
		logx.FromContext(r.Context()).Error("vault setup failed", "err", err.Error())
		setFlash(w, "Failed to set up vault.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}

	if err := s.DB.SetVaultSentinel(sentinel); err != nil {
		logx.FromContext(r.Context()).Error("vault save sentinel failed", "err", err.Error())
		setFlash(w, "Failed to save vault configuration.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	cacheVaultPassword(sessionToken, password)

	s.auditServer(r, "vault_setup", "critical", "setup", "vault", "",
		"Password vault initialized", nil)

	setFlash(w, "Vault created and unlocked.")
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

// HandleVaultUnlock verifies the vault password and caches it in memory.
func (s *Server) HandleVaultUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	password := r.FormValue("vault_password")
	sentinel, err := s.DB.GetVaultSentinel()
	if err != nil || sentinel == "" {
		setFlash(w, "Vault is not set up.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}

	if !crypto.VaultVerifySentinel(sentinel, password, s.AppKey) {
		s.auditServer(r, "vault_unlock_failed", "warn", "unlock", "vault", "",
			"Failed vault unlock attempt", nil)
		setFlash(w, "Incorrect vault password.")
		http.Redirect(w, r, "/vault", http.StatusSeeOther)
		return
	}

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	cacheVaultPassword(sessionToken, password)

	s.auditServer(r, "vault_unlocked", "info", "unlock", "vault", "",
		"Vault unlocked", nil)

	setFlash(w, "Vault unlocked.")
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

// HandleVaultLock clears the cached vault password.
func (s *Server) HandleVaultLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	clearVaultPassword(sessionToken)

	setFlash(w, "Vault locked.")
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

// HandleVaultSave saves or updates a vault entry for a node.
func (s *Server) HandleVaultSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Parse form/JSON before CSRF check so FormValue works
	r.ParseMultipartForm(1 << 20)

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	vaultPW := getCachedVaultPassword(sessionToken)
	if vaultPW == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Vault is locked"})
		return
	}

	var nodeID uint64
	var entryType, value string

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var req struct {
			NodeID    uint64 `json:"node_id"`
			EntryType string `json:"entry_type"`
			Value     string `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		nodeID = req.NodeID
		entryType = req.EntryType
		value = req.Value
	} else {
		nodeID, _ = strconv.ParseUint(r.FormValue("node_id"), 10, 64)
		entryType = r.FormValue("entry_type")
		value = r.FormValue("value")
	}

	if nodeID == 0 || entryType == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing node_id or entry_type"})
		return
	}

	if value == "" {
		if err := s.DB.RawExec("DELETE FROM vault_entries WHERE node_id = ? AND entry_type = ?", nodeID, entryType); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else {
		enc, err := crypto.VaultEncrypt(value, s.AppKey)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Encryption failed"})
			return
		}
		if err := s.DB.UpsertVaultEntry(nodeID, entryType, enc); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	}

	s.auditServer(r, "vault_entry_saved", "warn", "save", "vault_entry",
		fmt.Sprintf("%d", nodeID),
		fmt.Sprintf("Vault entry %s updated for node %d", entryType, nodeID), nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

// HandleVaultReveal returns a decrypted vault entry value. Audited.
func (s *Server) HandleVaultReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	vaultPW := getCachedVaultPassword(sessionToken)
	if vaultPW == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Vault is locked"})
		return
	}

	nodeID, _ := strconv.ParseUint(r.FormValue("node_id"), 10, 64)
	entryType := r.FormValue("entry_type")

	entries, err := s.DB.GetVaultEntries(nodeID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	for _, e := range entries {
		if e.EntryType == entryType {
			plain, err := crypto.VaultDecrypt(e.ValueEnc, s.AppKey)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "Decryption failed"})
				return
			}

			s.auditServer(r, "vault_revealed", "critical", "reveal", "vault_entry",
				fmt.Sprintf("%d", nodeID),
				fmt.Sprintf("Vault entry %s revealed for node %d", entryType, nodeID), nil)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"value": plain})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "Entry not found"})
}

// GetVaultSSHCreds returns cached SSH credentials from the vault for a node.
// Used by terminal/DR/update handlers to skip the SSH prompt.
func (s *Server) GetVaultSSHCreds(sessionToken string, nodeID uint64) (username, password string) {
	vaultPW := getCachedVaultPassword(sessionToken)
	if vaultPW == "" {
		return "", ""
	}
	entries, err := s.DB.GetVaultEntries(nodeID)
	if err != nil {
		return "", ""
	}
	for _, e := range entries {
		plain, err := crypto.VaultDecrypt(e.ValueEnc, s.AppKey)
		if err != nil {
			continue
		}
		switch e.EntryType {
		case "ssh_username":
			username = plain
		case "ssh_password":
			password = plain
		}
	}
	return username, password
}
