package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

type githubRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []githubAsset  `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// HandleServerUpdate downloads the latest release binary from GitHub, replaces
// the running binary, and restarts the systemd service.
func (s *Server) HandleServerUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	lg := logx.FromContext(r.Context())

	tuning, err := s.DB.GetServerTuning()
	if err != nil || tuning.LatestServerVersion == "" {
		setFlash(w, "Cannot update: latest version not known. Check for updates first.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	if tuning.LatestServerVersion == ServerVersion {
		setFlash(w, "Server is already up to date ("+ServerVersion+").")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	lg.Warn("server update: starting", "from", ServerVersion, "to", tuning.LatestServerVersion)

	releaseURL := "https://api.github.com/repos/lssolutions-ie/lss-backup-management-server/releases/tags/" + tuning.LatestServerVersion
	client := &http.Client{Timeout: 30 * time.Second}

	req, _ := http.NewRequest(http.MethodGet, releaseURL, nil)
	req.Header.Set("User-Agent", "LSS-Management-Server")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		lg.Error("server update: fetch release failed", "err", err.Error())
		setFlash(w, "Update failed: could not fetch release info.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		lg.Error("server update: GitHub API error", "status", resp.StatusCode)
		setFlash(w, fmt.Sprintf("Update failed: GitHub returned %d.", resp.StatusCode))
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		lg.Error("server update: decode release failed", "err", err.Error())
		setFlash(w, "Update failed: could not parse release.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == "lss-management-server" {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		lg.Error("server update: no binary asset in release")
		setFlash(w, "Update failed: no binary found in release.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	lg.Info("server update: downloading binary", "url", downloadURL)

	dlReq, _ := http.NewRequest(http.MethodGet, downloadURL, nil)
	dlReq.Header.Set("User-Agent", "LSS-Management-Server")
	dlResp, err := client.Do(dlReq)
	if err != nil {
		lg.Error("server update: download failed", "err", err.Error())
		setFlash(w, "Update failed: could not download binary.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		lg.Error("server update: download returned non-200", "status", dlResp.StatusCode)
		setFlash(w, fmt.Sprintf("Update failed: download returned %d.", dlResp.StatusCode))
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	tmpFile, err := os.CreateTemp("", "lss-server-update-*")
	if err != nil {
		lg.Error("server update: create temp file failed", "err", err.Error())
		setFlash(w, "Update failed: could not create temp file.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, dlResp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		lg.Error("server update: write binary failed", "err", err.Error())
		setFlash(w, "Update failed: could not write binary.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		lg.Error("server update: chmod failed", "err", err.Error())
		setFlash(w, "Update failed: could not set permissions.")
		http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)
		return
	}

	binaryPath := "/usr/local/bin/lss-management-server"

	s.auditServer(r, "server_update", "critical", "update", "server", "",
		fmt.Sprintf("Server update from %s to %s", ServerVersion, tuning.LatestServerVersion), nil)

	lg.Warn("server update: replacing binary and restarting", "from", ServerVersion, "to", tuning.LatestServerVersion)

	// Send response before restarting — the browser will see the flash after reload.
	setFlash(w, fmt.Sprintf("Server updated to %s. Restarting...", tuning.LatestServerVersion))
	http.Redirect(w, r, "/settings/updates", http.StatusSeeOther)

	// Flush response to the client before we die.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Replace binary and restart in a goroutine so the HTTP response completes.
	go func() {
		time.Sleep(500 * time.Millisecond)

		if err := os.Rename(tmpPath, binaryPath); err != nil {
			lg.Error("server update: rename failed, trying copy", "err", err.Error())
			src, err2 := os.Open(tmpPath)
			if err2 != nil {
				lg.Error("server update: copy open failed", "err", err2.Error())
				return
			}
			dst, err2 := os.OpenFile(binaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err2 != nil {
				src.Close()
				lg.Error("server update: copy create failed", "err", err2.Error())
				return
			}
			io.Copy(dst, src)
			src.Close()
			dst.Close()
			os.Remove(tmpPath)
		}

		exec.Command("systemctl", "restart", "lss-management").Run()
	}()
}
