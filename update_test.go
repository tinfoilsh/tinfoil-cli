package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		current, latest string
		want            bool
	}{
		{"0.16.3", "0.16.4", true},
		{"0.16.3", "0.17.0", true},
		{"0.16.3", "1.0.0", true},
		{"0.16.3", "0.16.3", false},
		{"0.16.3", "0.16.2", false},
		{"0.16.3", "v0.16.4", true},
		{"v0.16.3", "0.16.4", true},
		{"0.16.3", "0.16.4-rc.1", true},
		{"0.16.4-rc.1", "0.16.4", true},
		{"dev", "0.16.4", false},
		{"0.16.3", "", false},
		{"0.16.3", "latest", false},
	}
	for _, tt := range tests {
		if got := isNewerVersion(tt.current, tt.latest); got != tt.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func newTestUpdateChecker(t *testing.T, current string, handler http.HandlerFunc) (*updateChecker, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	return &updateChecker{
		current:    current,
		releaseURL: server.URL,
		cachePath:  filepath.Join(t.TempDir(), updateCacheFileName),
		http:       server.Client(),
		now:        func() time.Time { return now },
	}, &requests
}

func releaseHandler(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"tag_name":"`+tag+`"}`)
	}
}

func TestNewerVersionReportsNewerRelease(t *testing.T) {
	checker, _ := newTestUpdateChecker(t, "0.16.3", releaseHandler("v0.17.0"))

	latest, ok := checker.newerVersion()
	if !ok || latest != "0.17.0" {
		t.Fatalf("newerVersion() = (%q, %v), want (%q, true)", latest, ok, "0.17.0")
	}
}

func TestNewerVersionQuietWhenUpToDate(t *testing.T) {
	checker, _ := newTestUpdateChecker(t, "0.17.0", releaseHandler("v0.17.0"))

	if latest, ok := checker.newerVersion(); ok {
		t.Fatalf("newerVersion() = (%q, true), want no update", latest)
	}
}

func TestNewerVersionQuietOnAPIFailure(t *testing.T) {
	checker, _ := newTestUpdateChecker(t, "0.16.3", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	})

	if latest, ok := checker.newerVersion(); ok {
		t.Fatalf("newerVersion() = (%q, true), want no update on API failure", latest)
	}
	if _, err := os.Stat(checker.cachePath); !os.IsNotExist(err) {
		t.Fatalf("cache should not be written on failure, stat err = %v", err)
	}
}

func TestNewerVersionCachesLookup(t *testing.T) {
	checker, requests := newTestUpdateChecker(t, "0.16.3", releaseHandler("v0.17.0"))

	for i := 0; i < 3; i++ {
		if _, ok := checker.newerVersion(); !ok {
			t.Fatalf("iteration %d: expected an update", i)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("GitHub API requests = %d, want 1 (later calls should hit the cache)", got)
	}

	data, err := os.ReadFile(checker.cachePath)
	if err != nil {
		t.Fatalf("reading cache: %v", err)
	}
	var cached updateCache
	if err := json.Unmarshal(data, &cached); err != nil {
		t.Fatalf("decoding cache: %v", err)
	}
	if cached.LatestVersion != "0.17.0" || !cached.CheckedAt.Equal(checker.now()) {
		t.Fatalf("cache = %+v, want latest 0.17.0 checked at %v", cached, checker.now())
	}
}

func TestNewerVersionRefetchesWhenCacheExpired(t *testing.T) {
	checker, requests := newTestUpdateChecker(t, "0.16.3", releaseHandler("v0.17.0"))

	stale := updateCache{
		CheckedAt:     checker.now().Add(-updateCheckInterval),
		LatestVersion: "0.16.3",
	}
	data, _ := json.Marshal(stale)
	if err := os.WriteFile(checker.cachePath, data, 0o600); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	latest, ok := checker.newerVersion()
	if !ok || latest != "0.17.0" {
		t.Fatalf("newerVersion() = (%q, %v), want refreshed (%q, true)", latest, ok, "0.17.0")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("GitHub API requests = %d, want 1 after cache expiry", got)
	}
}

func TestNewerVersionIgnoresMalformedCache(t *testing.T) {
	checker, requests := newTestUpdateChecker(t, "0.16.3", releaseHandler("v0.17.0"))

	if err := os.WriteFile(checker.cachePath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	if latest, ok := checker.newerVersion(); !ok || latest != "0.17.0" {
		t.Fatalf("newerVersion() = (%q, %v), want (%q, true)", latest, ok, "0.17.0")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("GitHub API requests = %d, want 1", got)
	}
}

func TestUpdateCheckDisabledForDevBuildsAndOptOut(t *testing.T) {
	setVersionForTest(t, defaultVersion)
	t.Setenv(envNoUpdateCheck, "")
	if updateCheckEnabled() {
		t.Fatal("update check should be disabled for dev builds")
	}

	setVersionForTest(t, "0.16.3")
	t.Setenv(envNoUpdateCheck, "1")
	if updateCheckEnabled() {
		t.Fatalf("update check should be disabled when %s is set", envNoUpdateCheck)
	}
}

func TestStartUpdateCheckReturnsNothingWhenDisabled(t *testing.T) {
	setVersionForTest(t, defaultVersion)

	if latest, ok := startUpdateCheck()(); ok {
		t.Fatalf("startUpdateCheck() = (%q, true), want disabled", latest)
	}
}
