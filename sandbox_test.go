package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSandboxStartReusesSavedConfiguration(t *testing.T) {
	for _, state := range []string{statusStopped, statusFailed} {
		t.Run(state, func(t *testing.T) {
			row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Status: state,
				ConfigName: "/tinfoil/containers/saved-digest", Variables: json.RawMessage(`{}`),
				Config: "containers:\n  - env:\n      - MONITOR_ROUTE: '{\"domain\":\"personal.example\"}'\n"}
			var starts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /api/auth/context":
					json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "user_1"})
				case "GET /api/containers":
					json.NewEncoder(w).Encode([]containerView{row})
				case "GET /api/containers/work-id":
					json.NewEncoder(w).Encode(row)
				case "POST /api/containers/work-id/deploy":
					starts.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || len(body) != 0 {
						t.Errorf("start must reuse saved config without overrides: body=%s err=%v", body, err)
					}
					// Stop before enrollment while checking that boot errors propagate.
					json.NewEncoder(w).Encode(containerView{Name: row.Name, Status: statusFailed, ErrorMessage: "test boot failure"})
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			t.Setenv(envCPURL, server.URL)
			t.Setenv(envAdminKey, "admin_test")
			_, err := startSandbox("work")
			require.ErrorContains(t, err, "test boot failure")
			require.EqualValues(t, 1, starts.Load())
		})
	}
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
