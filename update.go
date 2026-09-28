package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/term"
)

const (
	envNoUpdateCheck = "TINFOIL_NO_UPDATE_CHECK"

	latestReleaseURL    = "https://api.github.com/repos/tinfoilsh/tinfoil-cli/releases/latest"
	updateCommand       = "tinfoil update"
	updateCacheFileName = "update-check.json"
	updateCheckInterval = 24 * time.Hour
	updateCheckTimeout  = 2 * time.Second
	// updateNoticeWait bounds how long a finished command waits for the
	// background lookup so a slow GitHub never noticeably delays fast commands.
	updateNoticeWait = 200 * time.Millisecond
)

// updateCache remembers the most recent release lookup so that the CLI only
// hits the GitHub API once per updateCheckInterval.
type updateCache struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

type updateChecker struct {
	current    string
	releaseURL string
	cachePath  string
	http       *http.Client
	now        func() time.Time
}

func newUpdateChecker() (*updateChecker, error) {
	cfgPath, err := configPath()
	if err != nil {
		return nil, err
	}
	return &updateChecker{
		current:    version,
		releaseURL: latestReleaseURL,
		cachePath:  filepath.Join(filepath.Dir(cfgPath), updateCacheFileName),
		http:       updateHTTPClient(updateCheckTimeout),
		now:        time.Now,
	}, nil
}

// startUpdateCheck runs the release lookup in the background so it overlaps
// with the command being executed. The returned function waits at most
// updateNoticeWait for the lookup and reports the newer version, if there is
// one; a lookup that is still in flight is abandoned so the command exits
// promptly.
func startUpdateCheck() func() (string, bool) {
	if !updateCheckEnabled() {
		return func() (string, bool) { return "", false }
	}
	checker, err := newUpdateChecker()
	if err != nil {
		return func() (string, bool) { return "", false }
	}
	return checker.start(updateNoticeWait)
}

func (c *updateChecker) start(maxWait time.Duration) func() (string, bool) {
	type result struct {
		latest string
		ok     bool
	}
	done := make(chan result, 1)
	go func() {
		latest, ok := c.newerVersion()
		done <- result{latest, ok}
	}()
	return func() (string, bool) {
		select {
		case r := <-done:
			return r.latest, r.ok
		case <-time.After(maxWait):
			return "", false
		}
	}
}

// updateCheckEnabled skips the check for dev builds, when explicitly opted
// out, and when stderr is not a terminal so scripts never see the notice.
func updateCheckEnabled() bool {
	if version == defaultVersion {
		return false
	}
	if os.Getenv(envNoUpdateCheck) != "" {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// newerVersion returns the latest released version when it is newer than the
// running binary. All failures are swallowed: an update notice is a
// convenience and must never interfere with the command itself.
func (c *updateChecker) newerVersion() (string, bool) {
	latest := c.latestVersion()
	if latest == "" {
		return "", false
	}
	if !isNewerVersion(c.current, latest) {
		return "", false
	}
	return latest, true
}

func (c *updateChecker) latestVersion() string {
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

func (c *updateChecker) readCache() (updateCache, bool) {
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

func (c *updateChecker) writeCache(cached updateCache) {
	data, err := json.Marshal(cached)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.cachePath), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(c.cachePath, data, 0o600)
}

func (c *updateChecker) fetchLatestVersion() (string, error) {
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

func printUpdateNotice(latest string) {
	fmt.Fprintf(os.Stderr, "\nwarning: a new version of tinfoil is available (%s -> %s)\nupdate with: %s\n", version, latest, updateCommand)
}
