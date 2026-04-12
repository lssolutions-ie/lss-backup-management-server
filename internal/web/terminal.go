package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"golang.org/x/crypto/ssh"
)

// terminalPageData is used by templates/terminal.html.
type terminalPageData struct {
	PageData
	Node *models.Node
}

// terminalAuthMsg is the first WebSocket message the browser sends after the
// upgrade. It carries the SSH connect details.
type terminalAuthMsg struct {
	Type     string `json:"type"`
	NodeID   uint64 `json:"node_id"` // if set, server routes via the node's reverse tunnel
	Host     string `json:"host"`    // fallback when there's no tunnel
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
}

// terminalClientMsg is a subsequent message from the browser (keystrokes / resize).
type terminalClientMsg struct {
	Type string `json:"type"`           // "input" | "resize"
	Data string `json:"data,omitempty"` // input bytes
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// terminalServerMsg is a message from the server to the browser.
type terminalServerMsg struct {
	Type string `json:"type"` // "output" | "error" | "closed"
	Data string `json:"data,omitempty"`
}

var upgrader = websocket.Upgrader{
	// The default CheckOrigin rejects cross-origin WebSocket handshakes which
	// is what we want — the dashboard is served from the same origin.
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
}

// HandleTerminalPage renders the credential form + xterm.js page for a node.
// Served at GET /nodes/{id}/terminal.
func (s *Server) HandleTerminalPage(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "terminal.html", terminalPageData{
		PageData: s.newPageData(r),
		Node:     node,
	})
}

// HandleTerminalWS upgrades to a WebSocket and proxies bytes to an SSH session.
// Served at GET /ws/terminal. Auth is via the normal dashboard session cookie.
func (s *Server) HandleTerminalWS(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.CanWrite() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("terminal: upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	// Read the auth message.
	_ = ws.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, raw, err := ws.ReadMessage()
	if err != nil {
		return
	}
	_ = ws.SetReadDeadline(time.Time{})

	var auth terminalAuthMsg
	if err := json.Unmarshal(raw, &auth); err != nil || auth.Type != "auth" {
		wsSendError(ws, "invalid auth message")
		return
	}
	if auth.Username == "" {
		wsSendError(ws, "username is required")
		return
	}
	if auth.Cols <= 0 {
		auth.Cols = 80
	}
	if auth.Rows <= 0 {
		auth.Rows = 24
	}

	// Resolve the dial target. If the browser specified a node_id and that
	// node has a live reverse tunnel, dial 127.0.0.1:<tunnel_port>. Otherwise
	// fall back to the operator-supplied host/port (direct mode).
	dialHost := auth.Host
	dialPort := auth.Port
	viaTunnel := false
	if auth.NodeID > 0 {
		node, err := s.DB.GetNodeByID(auth.NodeID)
		if err != nil {
			wsSendError(ws, "node lookup failed")
			return
		}
		if node == nil {
			wsSendError(ws, "node not found")
			return
		}
		if node.TunnelReady() {
			dialHost = "127.0.0.1"
			dialPort = *node.TunnelPort
			viaTunnel = true
		}
	}
	if dialHost == "" {
		wsSendError(ws, "host is required (node has no active tunnel)")
		return
	}
	if dialPort == 0 {
		dialPort = 22
	}

	// NB: never log the password. Log enough to audit who connected where.
	mode := map[bool]string{true: "via-tunnel", false: "direct"}[viaTunnel]
	log.Printf("terminal: user=%s opening ssh %s=%s@%s:%d",
		user.Username, mode, auth.Username, dialHost, dialPort)
	sessionStart := time.Now()
	defer func() {
		log.Printf("terminal: user=%s closed ssh %s=%s@%s:%d duration=%s",
			user.Username, mode, auth.Username, dialHost, dialPort,
			time.Since(sessionStart).Truncate(time.Second))
	}()

	// Dial SSH.
	sshCfg := &ssh.ClientConfig{
		User:            auth.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(auth.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: TOFU store
		Timeout:         15 * time.Second,
	}
	// Drop the plaintext password from the auth struct ASAP; the cfg has its own copy.
	auth.Password = ""

	addr := fmt.Sprintf("%s:%d", dialHost, dialPort)
	sshClient, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		wsSendError(ws, "ssh dial failed: "+err.Error())
		return
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		wsSendError(ws, "ssh session failed: "+err.Error())
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", auth.Rows, auth.Cols, modes); err != nil {
		wsSendError(ws, "pty failed: "+err.Error())
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		wsSendError(ws, err.Error())
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		wsSendError(ws, err.Error())
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		wsSendError(ws, err.Error())
		return
	}

	if err := session.Shell(); err != nil {
		wsSendError(ws, "shell failed: "+err.Error())
		return
	}

	// Synchronise WS writes — multiple goroutines must not write concurrently
	// on a *websocket.Conn.
	var wsWriteMu sync.Mutex
	sendOutput := func(data []byte) error {
		msg := terminalServerMsg{Type: "output", Data: string(data)}
		b, _ := json.Marshal(msg)
		wsWriteMu.Lock()
		defer wsWriteMu.Unlock()
		return ws.WriteMessage(websocket.TextMessage, b)
	}

	// Proxy SSH stdout → WS
	done := make(chan struct{})
	go func() {
		copyPipeToWS(stdout, sendOutput)
		close(done)
	}()
	// Proxy SSH stderr → WS (same stream in a browser terminal)
	go copyPipeToWS(stderr, sendOutput)

	// Proxy WS → SSH stdin
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var msg terminalClientMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "input":
			if _, err := stdin.Write([]byte(msg.Data)); err != nil {
				break
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = session.WindowChange(msg.Rows, msg.Cols)
			}
		}
	}

	// Client closed or errored. Close the session and let the copy goroutines unwind.
	_ = session.Close()
	<-done

	// Final close notification (best-effort).
	wsWriteMu.Lock()
	b, _ := json.Marshal(terminalServerMsg{Type: "closed"})
	_ = ws.WriteMessage(websocket.TextMessage, b)
	wsWriteMu.Unlock()
}

// copyPipeToWS reads from an SSH pipe and forwards chunks to the browser.
func copyPipeToWS(r io.Reader, send func([]byte) error) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if sendErr := send(buf[:n]); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// wsSendError sends an error message and closes the connection.
func wsSendError(ws *websocket.Conn, msg string) {
	log.Printf("terminal: %s", msg)
	b, _ := json.Marshal(terminalServerMsg{Type: "error", Data: msg})
	_ = ws.WriteMessage(websocket.TextMessage, b)
}
