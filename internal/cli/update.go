package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/selfupdate"
	"golang.org/x/term"
)

const (
	envNoUpdateCheck = "TINFOIL_NO_UPDATE_CHECK"
	updateCommand    = "tinfoil update"
	// updateNoticeWait bounds how long a finished command waits for the
	// background lookup so a slow GitHub never noticeably delays fast commands.
	updateNoticeWait = 200 * time.Millisecond
)

func newUpdateChecker(currentVersion string, transport http.RoundTripper) (*selfupdate.Checker, error) {
	cfgPath, err := configPath()
	if err != nil {
		return nil, err
	}
	return selfupdate.NewChecker(currentVersion, filepath.Join(filepath.Dir(cfgPath), selfupdate.CacheFileName), time.Now, transport), nil
}

// startUpdateCheck runs the release lookup in the background so it overlaps
// with the command being executed. The returned function waits at most
// updateNoticeWait for the lookup and reports the newer version, if there is
// one; a lookup that is still in flight is abandoned so the command exits
// promptly.
func startUpdateCheck(streams commandIO, currentVersion string, transport http.RoundTripper) func() (string, bool) {
	if !updateCheckEnabled(streams, currentVersion) {
		return func() (string, bool) { return "", false }
	}
	checker, err := newUpdateChecker(currentVersion, transport)
	if err != nil {
		return func() (string, bool) { return "", false }
	}
	return startBackgroundUpdateCheck(checker.NewerVersion, updateNoticeWait)
}

func startBackgroundUpdateCheck(newerVersion func() (string, bool), maxWait time.Duration) func() (string, bool) {
	type result struct {
		latest string
		ok     bool
	}
	done := make(chan result, 1)
	go func() {
		latest, ok := newerVersion()
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
func updateCheckEnabled(streams commandIO, currentVersion string) bool {
	if currentVersion == defaultVersion {
		return false
	}
	if os.Getenv(envNoUpdateCheck) != "" {
		return false
	}
	return term.IsTerminal(streamFD(streams.err))
}

func printUpdateNotice(streams commandIO, currentVersion, latest string) {
	fmt.Fprintf(streams.err, "\n%s\n%s %s\n", dimText(fmt.Sprintf("warning: a new version of tinfoil is available (%s -> %s)", currentVersion, latest)), dimText("update with:"), valueText(updateCommand))
}
