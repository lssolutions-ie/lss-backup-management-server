package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// HandleRepoJobs is an API endpoint that SSHes into the node and
// retrieves job list with metadata (no snapshots).
func (s *Server) HandleRepoJobs(w http.ResponseWriter, r *http.Request) {
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

	output, err := sshExecOnNodeSudo(node, req.Username, req.Password, "lss-backup-cli repo-info --json --summary")
	if err != nil {
		log.Printf("repo: ssh exec node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleRepoSnapshots is an API endpoint that SSHes into the node and
// retrieves snapshots for a single job.
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
		JobID    string `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	cmd := fmt.Sprintf("lss-backup-cli repo-info --json --job %s", req.JobID)
	output, err := sshExecOnNodeSudo(node, req.Username, req.Password, cmd)
	if err != nil {
		log.Printf("repo: ssh exec node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

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

	output, err := sshExecOnNodeSudo(node, req.Username, req.Password, cmd)
	if err != nil {
		log.Printf("repo: ssh browse node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleRepoDownload streams a single file from a restic snapshot via SSH.
func (s *Server) HandleRepoDownload(w http.ResponseWriter, r *http.Request) {
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
		Path       string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !node.TunnelReady() || req.Path == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(req.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *node.TunnelPort)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		http.Error(w, "ssh dial failed", http.StatusBadGateway)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		http.Error(w, "ssh session failed", http.StatusBadGateway)
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		http.Error(w, "pipe failed", http.StatusInternalServerError)
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		http.Error(w, "stdin pipe failed", http.StatusInternalServerError)
		return
	}

	cmd := fmt.Sprintf("sudo -S lss-backup-cli repo-dump --json %s %s --path %s",
		req.JobID, req.SnapshotID, req.Path)

	if err := session.Start(cmd); err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}

	// Send password for sudo.
	fmt.Fprintf(stdin, "%s\n", req.Password)
	stdin.Close()

	// Extract filename from path.
	parts := bytes.Split([]byte(req.Path), []byte("/"))
	filename := string(parts[len(parts)-1])
	if filename == "" {
		filename = "download"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	// Stream the file content.
	io.Copy(w, stdout)
	session.Wait()

	log.Printf("repo: download node=%d file=%s", node.ID, req.Path)
}

// HandleRepoDownloadZip streams multiple files/dirs from a restic snapshot as a zip.
func (s *Server) HandleRepoDownloadZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	var req struct {
		Username   string   `json:"username"`
		Password   string   `json:"password"`
		JobID      string   `json:"job_id"`
		SnapshotID string   `json:"snapshot_id"`
		Paths      []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !node.TunnelReady() || len(req.Paths) == 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(req.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *node.TunnelPort)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		http.Error(w, "ssh dial failed", http.StatusBadGateway)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		http.Error(w, "ssh session failed", http.StatusBadGateway)
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		http.Error(w, "pipe failed", http.StatusInternalServerError)
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		http.Error(w, "stdin pipe failed", http.StatusInternalServerError)
		return
	}

	pathArgs := ""
	for _, p := range req.Paths {
		pathArgs += fmt.Sprintf(" --path %s", p)
	}
	cmd := fmt.Sprintf("sudo -S lss-backup-cli repo-dump-zip --json %s %s%s",
		req.JobID, req.SnapshotID, pathArgs)

	if err := session.Start(cmd); err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}

	fmt.Fprintf(stdin, "%s\n", req.Password)
	stdin.Close()

	shortID := req.SnapshotID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "snapshot-"+shortID+".zip"))

	io.Copy(w, stdout)
	session.Wait()

	log.Printf("repo: zip download node=%d paths=%d", node.ID, len(req.Paths))
}

// sshExecOnNodeSudo connects to a node via its reverse tunnel and runs a
// command with sudo, piping the password via stdin.
func sshExecOnNodeSudo(node *models.Node, username, password, command string) ([]byte, error) {
	if node.TunnelPort == nil || *node.TunnelPort == 0 {
		return nil, fmt.Errorf("no tunnel port")
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
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

	// Pipe password to sudo -S via stdin.
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	sudoCmd := fmt.Sprintf("sudo -S %s", command)
	if err := session.Start(sudoCmd); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}

	// Write password + newline for sudo prompt.
	_, _ = fmt.Fprintf(stdin, "%s\n", password)
	stdin.Close()

	if err := session.Wait(); err != nil {
		if stderr.Len() > 0 {
			// Strip the sudo password prompt from stderr.
			errStr := stderr.String()
			if idx := bytes.Index([]byte(errStr), []byte("\n")); idx >= 0 {
				errStr = errStr[idx+1:]
			}
			if errStr != "" {
				return nil, fmt.Errorf("%s", errStr)
			}
		}
		return nil, err
	}

	// stdout may contain the sudo password prompt on stderr, but stdout should be clean JSON.
	return stdout.Bytes(), nil
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
