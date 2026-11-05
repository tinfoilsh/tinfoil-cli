package main

import (
	"testing"
	"time"
)

func TestUpdateCheckDisabledForDevBuildsAndOptOut(t *testing.T) {
	setVersionForTest(t, defaultVersion)
	t.Setenv(envNoUpdateCheck, "")
	if updateCheckEnabled(testStreams()) {
		t.Fatal("update check should be disabled for dev builds")
	}

	setVersionForTest(t, "0.16.3")
	t.Setenv(envNoUpdateCheck, "1")
	if updateCheckEnabled(testStreams()) {
		t.Fatalf("update check should be disabled when %s is set", envNoUpdateCheck)
	}
}

func TestStartGivesUpOnSlowLookup(t *testing.T) {
	release := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() { close(release); <-done })
	wait := startBackgroundUpdateCheck(func() (string, bool) {
		defer close(done)
		<-release
		return "0.17.0", true
	}, 20*time.Millisecond)
	started := time.Now()
	latest, ok := wait()
	if ok {
		t.Fatalf("wait() = (%q, true), want to give up on a slow lookup", latest)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("wait() blocked for %v, want it bounded by maxWait", elapsed)
	}
}

func TestStartReturnsPromptResult(t *testing.T) {
	wait := startBackgroundUpdateCheck(func() (string, bool) { return "0.17.0", true }, 5*time.Second)
	if latest, ok := wait(); !ok || latest != "0.17.0" {
		t.Fatalf("wait() = (%q, %v), want (%q, true)", latest, ok, "0.17.0")
	}
}

func TestStartUpdateCheckReturnsNothingWhenDisabled(t *testing.T) {
	setVersionForTest(t, defaultVersion)

	if latest, ok := startUpdateCheck(testStreams())(); ok {
		t.Fatalf("startUpdateCheck() = (%q, true), want disabled", latest)
	}
}
