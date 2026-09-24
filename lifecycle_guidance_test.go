package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestBuildReadinessOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/github/repos/acme/app/build":
			if r.Method != http.MethodPost {
				t.Errorf("method %s", r.Method)
			}
			io.WriteString(w, `{"success":true,"version":"v1.2.3","workflow_run_url":"https://github.com/acme/app/actions"}`)
		case "/api/github/repos/acme/app/build/info":
			if r.Method != http.MethodGet {
				t.Errorf("method %s", r.Method)
			}
			io.WriteString(w, `{"success":true,"latest_tag":"v2.0.0","suggested_next_version":"v2.0.1","latest_release_tag":"v1.2.3","has_new_commits":true,"releases":[{"tag_name":"v1.2.3","name":"Release","html_url":"https://github.com/acme/app/releases/tag/v1.2.3","published_at":"2026-09-24T00:00:00Z","prerelease":false}]}`)
		case "/api/github/repos/acme/app/build/status":
			if r.Method != http.MethodGet || r.URL.Query().Get("version") != "v1.2.3" {
				t.Errorf("wrong status query: %s %s", r.Method, r.URL)
			}
			io.WriteString(w, `{"success":true,"version":"v1.2.3","run":null}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	configureRepoCommandTest(t, server.URL)
	repoVersion = "v1.2.3"
	oldStatus := repoStatusVersion
	repoStatusVersion = "v1.2.3"
	t.Cleanup(func() { repoStatusVersion = oldStatus })
	for _, tc := range []struct {
		name string
		run  func() error
		want []string
	}{
		{"queued", func() error { return repoBuildRunCmd.RunE(repoBuildRunCmd, []string{"acme/app"}) }, []string{"Queued release v1.2.3; not yet deployable", "tinfoil repo build status acme/app --version v1.2.3", "Build & Publish"}},
		{"info", func() error { return repoBuildInfoCmd.RunE(repoBuildInfoCmd, []string{"acme/app"}) }, []string{"Latest tag:             v2.0.0", "Latest GitHub release:  v1.2.3", "Published release:     v1.2.3 at 2026-09-24", "A tag alone is not deployable"}},
		{"status", func() error { return repoBuildStatusCmd.RunE(repoBuildStatusCmd, []string{"acme/app"}) }, []string{"waiting for workflow visibility", "not yet deployable", "tinfoil repo build info acme/app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureTestStdout(tc.run)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(out), want) {
					t.Fatalf("missing %q: %s", want, out)
				}
			}
		})
	}
}

func TestVolumeUnlockGuidance(t *testing.T) {
	var out bytes.Buffer
	printVolumeUnlockGuidance(&out, []volumeSlot{{Name: "data", KeySecret: "DISK_KEY"}, {Name: "manual"}})
	for _, want := range []string{"automatic unlock", "keyserver", "secret DISK_KEY outside Tinfoil", "does not establish unlock readiness", "optional/manual unlock", "workload-managed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
}

func TestShellQuotePreservesArguments(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skipf("%s is not installed", shell)
			}
			t.Setenv("HOME", t.TempDir())
			for _, value := range []string{"#app", "~", "~/data", "~root", "ordinary", "acme/app@v1", "", "single'quote", "a b", "$(printf injected)", "a\nb", "a#b", "a~b", "--not-an-option"} {
				t.Run(value, func(t *testing.T) {
					script := "set -- " + shellQuote(value) + `; printf '%s\n' "$#" "$1"`
					out, err := exec.Command(path, "-c", script).CombinedOutput()
					if err != nil || string(out) != "1\n"+value+"\n" {
						t.Fatalf("argument %q was changed by %s: output=%q err=%v", value, shell, out, err)
					}
				})
			}
		})
	}
}
