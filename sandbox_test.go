package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSandboxCreateRequiresMonitorBeforeAnySideEffects(t *testing.T) {
	old := sandboxMonitor
	sandboxMonitor = ""
	t.Cleanup(func() { sandboxMonitor = old })
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	require.ErrorContains(t, sandboxCreateCmd.RunE(sandboxCreateCmd, []string{"work"}), "--monitor is required")
	dir, err := sandboxKeyDir("work")
	require.NoError(t, err)
	require.NoDirExists(t, dir)
}

func TestSandboxReleaseDiscoveryPreservesExistingDeployments(t *testing.T) {
	var rows []containerView
	lookups := 0
	available := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/containers":
			json.NewEncoder(w).Encode(rows)
		case "/api/containers/work-id":
			json.NewEncoder(w).Encode(rows[0])
		case "/" + defaultSandboxRepo + "/releases/latest":
			require.Empty(t, r.Header.Get("Authorization"))
			lookups++
			if !available {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"tag_name": "v9.8.7"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	previousURL := workloadReleaseURL
	workloadReleaseURL = server.URL + "/%s/releases/latest"
	t.Cleanup(func() { workloadReleaseURL = previousURL })
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "admin_test"})
	_, tag, err := workloadRevision(client, "work", defaultSandboxRepo, "")
	require.NoError(t, err)
	require.Equal(t, "v9.8.7", tag)
	available = false
	_, tag, err = workloadRevision(client, "work", defaultSandboxRepo, "v10.0.0-rc.1")
	require.NoError(t, err)
	require.Equal(t, "v10.0.0-rc.1", tag)
	rows = []containerView{{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, CurrentTag: "v1.2.3"}}
	_, tag, err = workloadRevision(client, "work", defaultSandboxRepo, "")
	require.NoError(t, err)
	require.Equal(t, "v1.2.3", tag)
	_, _, err = workloadRevision(client, "work", defaultSandboxRepo, "v9.8.7")
	require.ErrorContains(t, err, "already uses v1.2.3")
	require.Equal(t, 1, lookups, "explicit tags and existing deployments need no release lookup")
	rows = nil
	_, tag, err = workloadRevision(client, "work", defaultSandboxRepo, "")
	require.ErrorContains(t, err, "use --tag")
	require.Empty(t, tag, "failed discovery must not fall back to a bundled release")
}

func TestSandboxNameRejectsNamesThatCannotBeDirectories(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "plain name", raw: "my-sandbox", want: "my-sandbox", valid: true},
		{name: "surrounding space is trimmed", raw: "  my-sandbox\n", want: "my-sandbox", valid: true},
		{name: "underscores and digits", raw: "box_2", want: "box_2", valid: true},
		{name: "longest allowed", raw: strings.Repeat("a", 63), want: strings.Repeat("a", 63), valid: true},
		{name: "too long", raw: strings.Repeat("a", 64)},
		{name: "empty", raw: ""},
		{name: "leading dash", raw: "-box"},
		{name: "path separator", raw: "a/b"},
		{name: "parent directory", raw: ".."},
		{name: "traversal", raw: "../../.ssh"},
		{name: "dot", raw: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sandboxName(tt.raw)
			if tt.valid {
				if err != nil {
					t.Fatalf("sandboxName(%q) failed: %v", tt.raw, err)
				}
				if got != tt.want {
					t.Fatalf("sandboxName(%q) = %q, want %q", tt.raw, got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("sandboxName(%q) = %q, want an error", tt.raw, got)
			}
		})
	}
}
