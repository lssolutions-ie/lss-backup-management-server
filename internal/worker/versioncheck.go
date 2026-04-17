package worker

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/db"
)

// VersionChecker polls the GitHub tags API periodically to discover the latest
// CLI release version. The result is cached in server_tuning so the dashboard
// can compare it against each node's reported cli_version.
type VersionChecker struct {
	db       *db.DB
	interval time.Duration
	repoURL  string
	client   *http.Client
}

func NewVersionChecker(d *db.DB) *VersionChecker {
	return &VersionChecker{
		db:       d,
		interval: 30 * time.Minute,
		repoURL:  "https://api.github.com/repos/lssolutions-ie/lss-backup-cli/tags?per_page=1",
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *VersionChecker) Start() {
	go c.run()
}

func (c *VersionChecker) run() {
	// Run once on startup, then on interval.
	c.tick()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for range t.C {
		c.tick()
	}
}

type githubTag struct {
	Name string `json:"name"`
}

func (c *VersionChecker) tick() {
	req, err := http.NewRequest(http.MethodGet, c.repoURL, nil)
	if err != nil {
		lg.Warn("version-check: build request failed", "err", err.Error())
		return
	}
	req.Header.Set("User-Agent", "LSS-Management-Server")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		lg.Warn("version-check: request failed", "err", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		lg.Warn("version-check: non-200 response", "status", resp.StatusCode)
		return
	}

	var tags []githubTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		lg.Warn("version-check: decode failed", "err", err.Error())
		return
	}

	if len(tags) == 0 {
		lg.Warn("version-check: no tags returned")
		return
	}

	latest := tags[0].Name
	if latest == "" {
		lg.Warn("version-check: empty tag name")
		return
	}

	if err := c.db.SetLatestCLIVersion(latest); err != nil {
		lg.Error("version-check: save failed", "err", err.Error())
		return
	}

	lg.Debug("version-check: cached latest CLI version", "version", latest)
}
