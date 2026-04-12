package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"golang.org/x/crypto/ssh"
)

// repoPageData is used by the repository viewer page.
type repoPageData struct {
	PageData
	Node *models.Node
}

// repoSnapshotsResponse is returned by the snapshots API endpoint.
type repoSnapshotsResponse struct {
	Jobs []repoJobInfo `json:"jobs"`
}

type repoJobInfo struct {
	JobID     string         `json:"job_id"`
	JobName   string         `json:"job_name"`
	Program   string         `json:"program"`
	Destination string       `json:"destination"`
	Snapshots []repoSnapshot `json:"snapshots"`
	Error     string         `json:"error,omitempty"`
}

type repoSnapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
}

type repoFileEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // "file" | "dir"
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
}

// HandleRepoPage renders the repository viewer page.
func (s *Server) HandleRepoPage(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "repository.html", repoPageData{
		PageData: s.newPageData(r),
		Node:     node,
	})
}

// HandleRepoSnapshots is an API endpoint that SSHes into the node and
// retrieves repository snapshots for all jobs.
func (s *Server) HandleRepoSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	output, err := sshExecOnNode(node, req.Username, req.Password, "lss-backup-cli repo-info --json")
	if err != nil {
		log.Printf("repo: ssh exec node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	// The CLI returns JSON directly — pass it through.
	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleRepoBrowse is an API endpoint that retrieves file listing for a
// specific snapshot.
func (s *Server) HandleRepoBrowse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		JobID      string `json:"job_id"`
		SnapshotID string `json:"snapshot_id"`
		Path       string `json:"path"` // subdirectory to browse, empty for root
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	cmd := fmt.Sprintf("lss-backup-cli repo-ls --json %s %s", req.JobID, req.SnapshotID)
	if req.Path != "" {
		cmd += fmt.Sprintf(" --path %s", req.Path)
	}

	output, err := sshExecOnNode(node, req.Username, req.Password, cmd)
	if err != nil {
		log.Printf("repo: ssh browse node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// sshExecOnNode connects to a node via its reverse tunnel and runs a command.
func sshExecOnNode(node *models.Node, username, password, command string) ([]byte, error) {
	if node.TunnelPort == nil || *node.TunnelPort == 0 {
		return nil, fmt.Errorf("no tunnel port")
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // tunnel is already authenticated
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *node.TunnelPort)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(command); err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%s", stderr.String())
		}
		return nil, err
	}

	return stdout.Bytes(), nil
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
