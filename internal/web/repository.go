package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
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
	if !s.EnforceBrowseRepo(w, r) {
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeView(w, r, node.ID) {
		return
	}
	s.render(w, r, http.StatusOK, "repository.html", repoPageData{
		PageData: s.newPageData(r),
		Node:     node,
	})
}

// getRepoSSHCreds extracts SSH credentials from the request body,
// falling back to cached credentials from the session.
func (s *Server) getRepoSSHCreds(r *http.Request, nodeID uint64, body []byte) (username, password string) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.Unmarshal(body, &req)

	sessionToken, _ := r.Context().Value(ctxSession).(string)

	if req.Username != "" {
		// Cache for this session+node.
		CacheSSHCreds(sessionToken, nodeID, req.Username, req.Password)
		return req.Username, req.Password
	}

	// Try cached.
	return GetCachedSSHCreds(sessionToken, nodeID)
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

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		jsonError(w, "ssh credentials required", http.StatusUnauthorized)
		return
	}

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	output, err := sshExecOnNodeSudo(node, username, password, cliPath(node.HwOS)+" repo-info --json --summary")
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

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		jsonError(w, "ssh credentials required", http.StatusUnauthorized)
		return
	}

	var req struct {
		JobID string `json:"job_id"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	cmd := fmt.Sprintf("%s repo-info --json --job %s", cliPath(node.HwOS), req.JobID)
	output, err := sshExecOnNodeSudo(node, username, password, cmd)
	if err != nil {
		log.Printf("repo: ssh exec node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleRepoBrowseRsync is an API endpoint that lists files in an rsync
// job's destination directory.
func (s *Server) HandleRepoBrowseRsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		jsonError(w, "ssh credentials required", http.StatusUnauthorized)
		return
	}

	var req struct {
		JobID string `json:"job_id"`
		Path  string `json:"path"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	cmd := fmt.Sprintf("%s repo-ls-rsync --json %s", cliPath(node.HwOS), req.JobID)
	if req.Path != "" {
		cmd += fmt.Sprintf(" --path %s", req.Path)
	}

	output, err := sshExecOnNodeSudo(node, username, password, cmd)
	if err != nil {
		log.Printf("repo: rsync browse node=%d: %v", node.ID, err)
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

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)
	if username == "" {
		jsonError(w, "ssh credentials required", http.StatusUnauthorized)
		return
	}

	var req struct {
		JobID      string `json:"job_id"`
		SnapshotID string `json:"snapshot_id"`
		Path       string `json:"path"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() {
		jsonError(w, "node has no active tunnel", http.StatusBadGateway)
		return
	}

	cmd := fmt.Sprintf("%s repo-ls --json %s %s", cliPath(node.HwOS), req.JobID, req.SnapshotID)
	if req.Path != "" {
		cmd += fmt.Sprintf(" --path %s", req.Path)
	}

	output, err := sshExecOnNodeSudo(node, username, password, cmd)
	if err != nil {
		log.Printf("repo: ssh browse node=%d: %v", node.ID, err)
		jsonError(w, "ssh command failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

// HandleRepoDownloadRsync streams a single file from an rsync destination via SSH.
func (s *Server) HandleRepoDownloadRsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)

	var req struct {
		JobID string `json:"job_id"`
		Path  string `json:"path"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() || req.Path == "" || username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
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
		s.Fail(w, r, http.StatusInternalServerError, err, "pipe failed")
		return
	}
	stdin, err := sshStartWithSudo(session, node, password, fmt.Sprintf("cat %s", req.Path))
	if err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}
	stdin.Close()

	parts := bytes.Split([]byte(req.Path), []byte("/"))
	filename := string(parts[len(parts)-1])
	if filename == "" {
		filename = "download"
	}

	s.auditServer(r, "repo_download", "info", "download", "repo",
		fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("Rsync file download from node %s: %s", node.Name, req.Path),
		map[string]string{
			"node_id": fmt.Sprintf("%d", node.ID),
			"job_id":  req.JobID,
			"path":    req.Path,
			"kind":    "rsync_file",
		})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	copyWithSessionKeepAlive(w, stdout, sessionToken, s.DB)
	session.Wait()

	log.Printf("repo: rsync download node=%d file=%s", node.ID, req.Path)
}

// HandleRepoDownloadRsyncZip streams multiple files/dirs from rsync destination as zip.
func (s *Server) HandleRepoDownloadRsyncZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)

	var req struct {
		JobID string   `json:"job_id"`
		Paths []string `json:"paths"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() || len(req.Paths) == 0 || username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
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
		s.Fail(w, r, http.StatusInternalServerError, err, "pipe failed")
		return
	}

	pathArgs := ""
	for _, p := range req.Paths {
		pathArgs += " " + p
	}
	stdin, err := sshStartWithSudo(session, node, password, fmt.Sprintf("tar cf - %s", pathArgs))
	if err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}
	stdin.Close()

	s.auditServer(r, "repo_download", "info", "download", "repo",
		fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("Rsync zip download from node %s (%d paths)", node.Name, len(req.Paths)),
		map[string]string{
			"node_id":     fmt.Sprintf("%d", node.ID),
			"job_id":      req.JobID,
			"path_count":  fmt.Sprintf("%d", len(req.Paths)),
			"kind":        "rsync_zip",
		})

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", req.JobID+".tar"))

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	copyWithSessionKeepAlive(w, stdout, sessionToken, s.DB)
	session.Wait()

	log.Printf("repo: rsync zip download node=%d paths=%d", node.ID, len(req.Paths))
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

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)

	var req struct {
		JobID      string `json:"job_id"`
		SnapshotID string `json:"snapshot_id"`
		Path       string `json:"path"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() || req.Path == "" || username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
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
		s.Fail(w, r, http.StatusInternalServerError, err, "pipe failed")
		return
	}

	cmd := fmt.Sprintf("%s repo-dump --json %s %s --path %s", cliPath(node.HwOS),
		req.JobID, req.SnapshotID, req.Path)
	stdin, err := sshStartWithSudo(session, node, password, cmd)
	if err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}
	stdin.Close()

	// Extract filename from path.
	parts := bytes.Split([]byte(req.Path), []byte("/"))
	filename := string(parts[len(parts)-1])
	if filename == "" {
		filename = "download"
	}

	s.auditServer(r, "repo_download", "info", "download", "repo",
		fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("Restic file download from node %s: %s", node.Name, req.Path),
		map[string]string{
			"node_id":     fmt.Sprintf("%d", node.ID),
			"job_id":      req.JobID,
			"snapshot_id": req.SnapshotID,
			"path":        req.Path,
			"kind":        "restic_file",
		})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	// Stream the file content, periodically touching the session to prevent idle timeout.
	sessionToken, _ := r.Context().Value(ctxSession).(string)
	copyWithSessionKeepAlive(w, stdout, sessionToken, s.DB)
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

	body, _ := io.ReadAll(r.Body)
	username, password := s.getRepoSSHCreds(r, node.ID, body)

	var req struct {
		JobID      string   `json:"job_id"`
		SnapshotID string   `json:"snapshot_id"`
		Paths      []string `json:"paths"`
	}
	json.Unmarshal(body, &req)

	if !node.TunnelReady() || len(req.Paths) == 0 || username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
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
		s.Fail(w, r, http.StatusInternalServerError, err, "pipe failed")
		return
	}
	pathArgs := ""
	for _, p := range req.Paths {
		pathArgs += fmt.Sprintf(" --path %s", p)
	}
	cmd := fmt.Sprintf("%s repo-dump-zip --json %s %s%s", cliPath(node.HwOS),
		req.JobID, req.SnapshotID, pathArgs)

	log.Printf("repo: zip cmd=%s", cmd)

	var stderr bytes.Buffer
	session.Stderr = &stderr

	stdin, err := sshStartWithSudo(session, node, password, cmd)
	if err != nil {
		http.Error(w, "command failed", http.StatusBadGateway)
		return
	}
	stdin.Close()

	shortID := req.SnapshotID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	s.auditServer(r, "repo_download", "info", "download", "repo",
		fmt.Sprintf("%d", node.ID),
		fmt.Sprintf("Restic zip download from node %s snapshot %s (%d paths)", node.Name, shortID, len(req.Paths)),
		map[string]string{
			"node_id":     fmt.Sprintf("%d", node.ID),
			"job_id":      req.JobID,
			"snapshot_id": req.SnapshotID,
			"path_count":  fmt.Sprintf("%d", len(req.Paths)),
			"kind":        "restic_zip",
		})

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "snapshot-"+shortID+".zip"))

	sessionToken, _ := r.Context().Value(ctxSession).(string)
	n, _ := copyWithSessionKeepAlive(w, stdout, sessionToken, s.DB)
	session.Wait()

	if stderr.Len() > 0 {
		log.Printf("repo: zip stderr node=%d: %s", node.ID, stderr.String())
	}
	log.Printf("repo: zip download node=%d paths=%d bytes=%d", node.ID, len(req.Paths), n)
}

// cliPath returns the full path to lss-backup-cli for the given OS.
func cliPath(hwOS string) string {
	if hwOS == "windows" {
		return `"C:\Program Files\LSS Backup\lss-backup-cli.exe"`
	}
	return "/usr/local/bin/lss-backup-cli"
}

// sshStartWithSudo starts a command on an SSH session, wrapping with sudo on
// non-Windows nodes. Returns the stdin pipe for writing the sudo password.
func sshStartWithSudo(session *ssh.Session, node *models.Node, password, command string) (io.WriteCloser, error) {
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}

	var cmd string
	if node.HwOS == "windows" {
		cmd = command
	} else {
		cmd = fmt.Sprintf("sudo -S %s", command)
	}

	if err := session.Start(cmd); err != nil {
		return nil, err
	}

	if node.HwOS != "windows" {
		fmt.Fprintf(stdin, "%s\n", password)
	}

	return stdin, nil
}

// copyWithSessionKeepAlive copies data while periodically touching the session
// to prevent idle timeout during long downloads.
func copyWithSessionKeepAlive(dst io.Writer, src io.Reader, sessionToken string, db *db.DB) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	lastTouch := time.Now()
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			// Touch session every 60 seconds during streaming.
			if time.Since(lastTouch) > 60*time.Second {
				_ = db.TouchSession(sessionToken)
				lastTouch = time.Now()
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// sshExecOnNodeSudo connects to a node via its reverse tunnel and runs a
// command with sudo (or without on Windows), piping the password via stdin.
func sshExecOnNodeSudo(node *models.Node, username, password, command string) ([]byte, error) {
	// Windows doesn't have sudo — the SSH user is already admin.
	if node.HwOS == "windows" {
		return sshExecOnNode(node, username, password, command)
	}

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
