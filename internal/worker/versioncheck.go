package worker

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/db"
)

// VersionChecker polls the GitHub tags API periodically to discover the latest
// CLI and server release versions. Results are cached in server_tuning so the
// dashboard can compare them against reported versions.
type VersionChecker struct {
	db            *db.DB
	cliRepoURL    string
	serverRepoURL string
	client        *http.Client
}

func NewVersionChecker(d *db.DB) *VersionChecker {
	return &VersionChecker{
		db:            d,
		cliRepoURL:    "https://api.github.com/repos/lssolutions-ie/lss-backup-cli/tags?per_page=1",
		serverRepoURL: "https://api.github.com/repos/lssolutions-ie/lss-backup-server/tags?per_page=1",
		client:        &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *VersionChecker) Start() {
	go c.run()
}

func (c *VersionChecker) run() {
	// Run once on startup, then on configurable interval.
	c.tick()
	for {
		interval := c.getInterval()
		time.Sleep(interval)
		c.tick()
	}
}

// getInterval reads the configured update check interval from the DB.
// Falls back to 30 minutes if the DB query fails or returns 0.
func (c *VersionChecker) getInterval() time.Duration {
	t, err := c.db.GetServerTuning()
	if err != nil || t.UpdateCheckIntervalMinutes == 0 {
		return 30 * time.Minute
	}
	return time.Duration(t.UpdateCheckIntervalMinutes) * time.Minute
}

type githubTag struct {
	Name string `json:"name"`
}

func (c *VersionChecker) tick() {
	c.CheckCLIVersion()
	c.CheckServerVersion()
}

// CheckCLIVersion fetches the latest CLI version and release notes from GitHub.
// Public so the "Check Now" handler can call it directly.
func (c *VersionChecker) CheckCLIVersion() (string, error) {
	version, notes, err := c.fetchLatestRelease("https://api.github.com/repos/lssolutions-ie/lss-backup-cli/releases/latest")
	if err != nil {
		lg.Warn("version-check: CLI request failed", "err", err.Error())
		return "", err
	}
	if version == "" {
		return "", nil
	}
	if err := c.db.SetLatestCLIVersion(version, notes); err != nil {
		lg.Error("version-check: save CLI version failed", "err", err.Error())
		return version, err
	}
	lg.Debug("version-check: cached latest CLI version", "version", version)
	return version, nil
}

// CheckServerVersion fetches the latest server version and release notes from GitHub.
// Public so the "Check Now" handler can call it directly.
func (c *VersionChecker) CheckServerVersion() (string, error) {
	version, notes, err := c.fetchLatestRelease("https://api.github.com/repos/lssolutions-ie/lss-backup-server/releases/latest")
	if err != nil {
		lg.Warn("version-check: server request failed", "err", err.Error())
		return "", err
	}
	if version == "" {
		return "", nil
	}
	if err := c.db.SetLatestServerVersion(version, notes); err != nil {
		lg.Error("version-check: save server version failed", "err", err.Error())
		return version, err
	}
	lg.Debug("version-check: cached latest server version", "version", version)
	return version, nil
}

// fetchLatestTag hits the GitHub tags API and returns the name of the first tag.
func (c *VersionChecker) fetchLatestTag(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "LSS-Management-Server")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		lg.Warn("version-check: non-200 response", "url", url, "status", resp.StatusCode)
		return "", nil
	}

	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", err
	}

	if len(tags) == 0 || tags[0].Name == "" {
		lg.Warn("version-check: no tags returned", "url", url)
		return "", nil
	}

	return tags[0].Name, nil
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
}

// fetchLatestRelease hits the GitHub releases API and returns the tag name and body.
func (c *VersionChecker) fetchLatestRelease(url string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "LSS-Management-Server")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		lg.Warn("version-check: non-200 response", "url", url, "status", resp.StatusCode)
		return "", "", nil
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}

	return rel.TagName, rel.Body, nil
}
