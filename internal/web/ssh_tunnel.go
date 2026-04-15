package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

var tunnelLg = logx.Component("tunnel")

// sshTunnelUpgrader is a separate upgrader from the dashboard terminal one so
// we can tune buffer sizes for bulk SSH traffic without affecting the
// interactive terminal path.
var sshTunnelUpgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	// CLI clients do not send an Origin header, gorilla's default accepts
	// that. Leave CheckOrigin nil.
}

// ssh-tunnel HMAC header constants.
const (
	sshTunnelHeaderUID  = "X-LSS-UID"
	sshTunnelHeaderTS   = "X-LSS-TS"
	sshTunnelHeaderMAC  = "X-LSS-HMAC"
	sshTunnelMaxSkewSec = 120 // ±2 minutes
	sshTunnelLocalAddr  = "127.0.0.1:22"
)

// HandleSSHTunnelWS accepts a WebSocket upgrade request from an LSS Backup
// CLI node, authenticates it via HMAC-PSK in HTTP headers, and proxies binary
// bytes bidirectionally to the local sshd. The node then drives SSH (using
// ssh.NewClientConn) over the WebSocket and holds a reverse TCP forward open
// through the restricted lss-tunnel user.
//
// This endpoint deliberately does NOT use the dashboard session middleware —
// nodes have no cookie and no dashboard user.
func (s *Server) HandleSSHTunnelWS(w http.ResponseWriter, r *http.Request) {
	uid := r.Header.Get(sshTunnelHeaderUID)
	tsStr := r.Header.Get(sshTunnelHeaderTS)
	mac := r.Header.Get(sshTunnelHeaderMAC)

	if uid == "" || tsStr == "" || mac == "" {
		http.Error(w, "missing auth headers", http.StatusUnauthorized)
		return
	}

	// Replay / clock skew guard. Reject anything outside ±2 min.
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid timestamp", http.StatusUnauthorized)
		return
	}
	now := time.Now().Unix()
	if ts < now-sshTunnelMaxSkewSec || ts > now+sshTunnelMaxSkewSec {
		tunnelLg.Warn("stale timestamp", "uid", uid, "skew_sec", now-ts)
		http.Error(w, "stale timestamp", http.StatusUnauthorized)
		return
	}

	// Look up the node and decrypt the stored PSK.
	node, err := s.DB.GetNodeByUID(uid)
	if err != nil {
		tunnelLg.Error("lookup failed", "uid", uid, "err", err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if node == nil {
		tunnelLg.Warn("unknown uid", "uid", uid)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	psk, err := crypto.DecryptPSK(node.PSKEncrypted, s.AppKey)
	if err != nil {
		tunnelLg.Error("psk decrypt failed", "node_id", node.ID, "err", err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// HMAC-SHA256(psk, "ssh-tunnel|<uid>|<ts>")
	expected := computeTunnelHMAC(psk, uid, tsStr)
	// Drop psk reference asap; the HMAC has already been computed.
	psk = "" //nolint:ineffassign
	if subtle.ConstantTimeCompare([]byte(expected), []byte(mac)) != 1 {
		tunnelLg.Warn("hmac mismatch", "node_id", node.ID, "uid", uid)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket.
	ws, err := sshTunnelUpgrader.Upgrade(w, r, nil)
	if err != nil {
		tunnelLg.Error("upgrade failed", "node_id", node.ID, "err", err.Error())
		return
	}
	defer ws.Close() //nolint:errcheck

	// Dial the local sshd. Short timeout so a misconfigured sshd fails fast.
	tcp, err := net.DialTimeout("tcp", sshTunnelLocalAddr, 5*time.Second)
	if err != nil {
		tunnelLg.Error("dial sshd failed", "addr", sshTunnelLocalAddr, "node_id", node.ID, "err", err.Error())
		_ = ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "sshd unreachable"),
			time.Now().Add(time.Second),
		)
		return
	}
	defer tcp.Close() //nolint:errcheck

	// Mark tunnel as connected in the DB so the dashboard shows it as active.
	if err := s.DB.SetTunnelConnected(node.ID, true); err != nil {
		tunnelLg.Error("set connected failed", "node_id", node.ID, "err", err.Error())
	}

	tunnelLg.Info("open", "node_id", node.ID, "uid", uid, "peer", r.RemoteAddr)

	// Proxy bytes until either side closes.
	proxySSHTunnelBytes(ws, tcp)

	if err := s.DB.SetTunnelConnected(node.ID, false); err != nil {
		tunnelLg.Error("set disconnected failed", "node_id", node.ID, "err", err.Error())
	}

	tunnelLg.Info("closed", "node_id", node.ID, "uid", uid)
}

// computeTunnelHMAC returns HMAC-SHA256(psk, "ssh-tunnel:<uid>:<ts>") as lowercase hex.
// The separator is a colon (matching CLI v2.1.135+); the original pipe-based
// spec from the protocol negotiation was superseded when the CLI shipped.
func computeTunnelHMAC(psk, uid, ts string) string {
	h := hmac.New(sha256.New, []byte(psk))
	h.Write([]byte("ssh-tunnel:" + uid + ":" + ts))
	return hex.EncodeToString(h.Sum(nil))
}

// proxySSHTunnelBytes shuffles binary frames in both directions until either
// the WebSocket or the TCP connection closes, then tears both down.
func proxySSHTunnelBytes(ws *websocket.Conn, tcp net.Conn) {
	done := make(chan struct{}, 2)

	// WS -> TCP
	go func() {
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if msgType != websocket.BinaryMessage {
				// SSH traffic must be binary. Ignore anything else.
				continue
			}
			if _, werr := tcp.Write(data); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	// TCP -> WS
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	// One direction stopped — tear down everything so the other goroutine unblocks.
	_ = tcp.Close()
	_ = ws.Close()
	<-done
}
