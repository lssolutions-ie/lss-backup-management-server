package web

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/logx"
)

var assetSyncLg = logx.Component("asset-sync")

// SyncAssetsIfNeeded checks if the on-disk templates/migrations/static match
// the running binary version. If not, downloads and installs fresh assets from
// the GitHub release. This self-heals after a binary-only update.
func SyncAssetsIfNeeded(version, configDir string) {
	if version == "" || version == "dev" {
		return
	}

	versionFile := filepath.Join(configDir, ".asset-version")
	existing, _ := os.ReadFile(versionFile)
	if strings.TrimSpace(string(existing)) == version {
		return
	}

	assetSyncLg.Info("asset version mismatch — syncing",
		"binary_version", version,
		"asset_version", strings.TrimSpace(string(existing)))

	repo := "lssolutions-ie/lss-backup-server"
	tarURL := fmt.Sprintf("https://github.com/%s/archive/refs/tags/%s.tar.gz", repo, version)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(tarURL)
	if err != nil {
		assetSyncLg.Error("asset sync: download failed", "err", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		assetSyncLg.Error("asset sync: non-200 response", "status", resp.StatusCode)
		return
	}

	tmpDir, err := os.MkdirTemp("", "lss-asset-sync-*")
	if err != nil {
		assetSyncLg.Error("asset sync: create temp dir failed", "err", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		assetSyncLg.Error("asset sync: gzip failed", "err", err.Error())
		return
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			assetSyncLg.Error("asset sync: tar read failed", "err", err.Error())
			return
		}
		// Strip the top-level directory (e.g., lss-backup-server-v1.29.8/)
		parts := strings.SplitN(hdr.Name, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		rel := parts[1]

		// Only extract templates/, migrations/, static/
		if !strings.HasPrefix(rel, "templates/") &&
			!strings.HasPrefix(rel, "migrations/") &&
			!strings.HasPrefix(rel, "static/") {
			continue
		}

		target := filepath.Join(tmpDir, rel)
		if hdr.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		f, err := os.Create(target)
		if err != nil {
			continue
		}
		io.Copy(f, tr)
		f.Close()
	}

	updated := 0
	for _, asset := range []string{"templates", "migrations", "static"} {
		srcDir := filepath.Join(tmpDir, asset)
		dstDir := filepath.Join(configDir, asset)
		if _, err := os.Stat(srcDir); os.IsNotExist(err) {
			continue
		}
		os.RemoveAll(dstDir)
		if err := copyDirRecursive(srcDir, dstDir); err != nil {
			assetSyncLg.Error("asset sync: copy failed", "asset", asset, "err", err.Error())
			continue
		}
		updated++
	}

	if updated > 0 {
		os.WriteFile(versionFile, []byte(version), 0644)
		// Fix ownership to match config dir
		exec.Command("chown", "-R", "lss-backup-server:lss-backup-server", configDir).Run()
		assetSyncLg.Info("asset sync complete", "version", version, "assets_updated", updated)
	}
}

func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}
