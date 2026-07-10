package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRepository(t *testing.T) {
	tests := []struct {
		value     string
		wantOwner string
		wantRepo  string
		wantError bool
	}{
		{value: "tinfoilsh/example", wantOwner: "tinfoilsh", wantRepo: "example"},
		{value: " tinfoilsh/example ", wantOwner: "tinfoilsh", wantRepo: "example"},
		{value: "example", wantError: true},
		{value: "/example", wantError: true},
		{value: "tinfoilsh/", wantError: true},
		{value: "tinfoilsh/example/extra", wantError: true},
		{value: "../example", wantError: true},
		{value: "./example", wantError: true},
		{value: "tinfoilsh/..", wantError: true},
		{value: "tinfoilsh/.", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			repository, err := parseRepository(tt.value)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRepository: %v", err)
			}
			if repository.owner != tt.wantOwner || repository.name != tt.wantRepo {
				t.Fatalf("got %q/%q, want %q/%q", repository.owner, repository.name, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

func TestRepoConfigPRUsesAdminKeyAndRawConfig(t *testing.T) {
	raw := "cpus: 2\nmemory: 8192\ncontainers: []\n"
	path := filepath.Join(t.TempDir(), "tinfoil-config.yml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/github/repos/acme/app/config/pr" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin_test" {
			t.Errorf("authorization = %q", got)
		}
		var body struct {
			Raw    string `json:"raw"`
			PRBody string `json:"pr_body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Raw != raw {
			t.Errorf("raw config changed: %q", body.Raw)
		}
		if body.PRBody != "Update resources" {
			t.Errorf("pr_body = %q", body.PRBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"pr_url":"https://github.com/acme/app/pull/4","pr_number":4,"branch":"tinfoil/config-update-4"}`)
	}))
	defer server.Close()

	configureRepoCommandTest(t, server.URL)
	repoConfigFile = path
	repoPRBody = "Update resources"

	if err := repoConfigPRCmd.RunE(repoConfigPRCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("run config pr: %v", err)
	}
}

func TestRepoBuildRunDispatchesVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/github/repos/acme/app/build" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body["version"] != "v1.2.3" {
			t.Errorf("version = %q", body["version"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"version":"v1.2.3","workflow_run_url":"https://github.com/acme/app/actions"}`)
	}))
	defer server.Close()

	configureRepoCommandTest(t, server.URL)
	repoVersion = "v1.2.3"

	if err := repoBuildRunCmd.RunE(repoBuildRunCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("run build: %v", err)
	}
}

func TestReadConfigInputRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.yml")
	data := make([]byte, maxConfigFileBytes+1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := readConfigInput(path); err == nil {
		t.Fatal("expected oversized config error")
	}
}

func configureRepoCommandTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAPIKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))

	previousOutput := outputFormat
	previousFile := repoConfigFile
	previousBody := repoPRBody
	previousVersion := repoVersion
	outputFormat = "table"
	repoConfigFile = ""
	repoPRBody = ""
	repoVersion = ""
	t.Cleanup(func() {
		outputFormat = previousOutput
		repoConfigFile = previousFile
		repoPRBody = previousBody
		repoVersion = previousVersion
	})
}
