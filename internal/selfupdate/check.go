package selfupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	latestReleaseURL    = "https://api.github.com/repos/tinfoilsh/tinfoil-cli/releases/latest"
	CacheFileName       = "update-check.json"
	updateCheckInterval = 24 * time.Hour
	updateCheckTimeout  = 2 * time.Second
)

// updateCache remembers the most recent release lookup so that the CLI only
// hits the GitHub API once per updateCheckInterval.
type updateCache struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

type Checker struct {
	current    string
	releaseURL string
	cachePath  string
	http       *http.Client
	now        func() time.Time
}

func NewChecker(current, cachePath string, now func() time.Time) *Checker {
	return &Checker{
		current:    current,
		releaseURL: latestReleaseURL,
		cachePath:  cachePath,
		http:       updateHTTPClient(updateCheckTimeout),
		now:        now,
	}
}

// NewerVersion returns the latest released version when it is newer than the
// running binary. All failures are swallowed: an update notice is a
// convenience and must never interfere with the command itself.
func (c *Checker) NewerVersion() (string, bool) {
	latest := c.latestVersion()
	if latest == "" {
		return "", false
	}
	if !isNewerVersion(c.current, latest) {
		return "", false
	}
	return latest, true
}

func (c *Checker) latestVersion() string {
	if cached, ok := c.readCache(); ok {
		return cached.LatestVersion
	}
	latest, err := c.fetchLatestVersion()
	if err != nil {
		return ""
	}
	c.writeCache(updateCache{CheckedAt: c.now(), LatestVersion: latest})
	return latest
}

func (c *Checker) readCache() (updateCache, bool) {
	data, err := os.ReadFile(c.cachePath)
	if err != nil {
		return updateCache{}, false
	}
	var cached updateCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return updateCache{}, false
	}
	age := c.now().Sub(cached.CheckedAt)
	if cached.LatestVersion == "" || age < 0 || age >= updateCheckInterval {
		return updateCache{}, false
	}
	return cached, true
}

func (c *Checker) writeCache(cached updateCache) {
	data, err := json.Marshal(cached)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.cachePath), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(c.cachePath, data, 0o600)
}

func (c *Checker) fetchLatestVersion() (string, error) {
	release, err := fetchUpdateRelease(context.Background(), c.http, c.releaseURL, c.current)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

// isNewerVersion compares two release versions such as "0.16.3". Anything that
// is not valid semver is treated as not upgradable so odd builds stay quiet.
func isNewerVersion(current, latest string) bool {
	cur := "v" + strings.TrimPrefix(current, "v")
	lat := "v" + strings.TrimPrefix(latest, "v")
	if !semver.IsValid(cur) || !semver.IsValid(lat) {
		return false
	}
	return semver.Compare(lat, cur) > 0
}
