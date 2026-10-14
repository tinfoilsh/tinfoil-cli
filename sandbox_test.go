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

func TestSandboxStartUsesSavedAliasWithoutMonitorLookup(t *testing.T) {
	for _, state := range []string{statusStopped, statusFailed, statusRunning} {
		t.Run(state, func(t *testing.T) {
			const monitorID = "11111111-1111-4111-8111-111111111111"
			row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Status: state,
				ConfigName:    "/tinfoil/containers/saved-digest",
				Config:        "containers:\n  - env:\n      - MONITOR_BINDING: '{\"container_id\":\"" + monitorID + "\",\"owner_public_key\":\"owner\"}'\n",
				NetworkPolicy: &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}}
			var starts atomic.Int32
			var mutations []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					mutations = append(mutations, r.URL.Path)
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Empty(t, body, "start and restart must not send boot variables")
				}
				switch r.Method + " " + r.URL.Path {
				case "GET /api/auth/context":
					json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "user_1"})
				case "GET /api/containers":
					json.NewEncoder(w).Encode([]containerView{row})
				case "POST /api/containers/work-id/stop":
					row.Status = statusStopped
					json.NewEncoder(w).Encode(row)
				case "GET /api/containers/work-id":
					json.NewEncoder(w).Encode(row)
				case "POST /api/containers/work-id/deploy":
					starts.Add(1)
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
			client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "test"})
			_, err := startSandboxRow(client, row, state == statusRunning)
			require.ErrorContains(t, err, "test boot failure")
			require.EqualValues(t, 1, starts.Load())
			expected := []string{"/api/containers/work-id/deploy"}
			if state == statusRunning {
				expected = append([]string{"/api/containers/work-id/stop"}, expected...)
			}
			require.Equal(t, expected, mutations)
		})
	}
}

func TestSandboxRequiresBoundRestrictedAliasBeforeStoppingOrDeploying(t *testing.T) {
	const monitorID = "11111111-1111-4111-8111-111111111111"
	row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo,
		Config: "containers:\n  - env:\n      - MONITOR_BINDING: '{\"container_id\":\"" + monitorID + "\",\"owner_public_key\":\"owner\"}'\n"}
	peer := containerPeer{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid policy made a request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "test"})
	for _, policy := range []*containerNetworkPolicy{nil, {}, {Public: true}, {EgressMode: "unrestricted"},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22}}},
		{Public: true, EgressMode: "restricted", Egress: []containerPeer{peer}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 443, Alias: peer.Alias}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: "other", Port: 22, Alias: peer.Alias}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "100.127.255.253", Port: 22}}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 23}}}},
		{EgressMode: "restricted", Egress: []containerPeer{peer, peer}}} {
		row.NetworkPolicy = policy
		for _, state := range []string{statusRunning, statusStopped} {
			row.Status = state
			_, err := startSandboxRow(client, row, state == statusRunning)
			require.ErrorContains(t, err, "TCP alias")
		}
	}
	row.NetworkPolicy = &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{peer}}
	require.NoError(t, validateSandboxNetwork(row))
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

func TestSandboxCreateSendsExplicitAliasWithoutMonitorLookup(t *testing.T) {
	const monitorID = "11111111-1111-4111-8111-111111111111"
	creates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/containers/validate":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"valid": true, "config": map[string]any{}}))
		case "POST /api/containers":
			creates++
			var body struct {
				Variables map[string]string       `json:"variables"`
				Policy    *containerNetworkPolicy `json:"network_policy"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.NotContains(t, body.Variables, "MONITOR_ENDPOINT")
			require.Equal(t, &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}, body.Policy)
			require.NoError(t, json.NewEncoder(w).Encode(containerView{ID: "sandbox", Name: "work", Status: statusRunning}))
		default:
			t.Errorf("unexpected endpoint lookup: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", 500)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	createRepo = defaultSandboxRepo
	createVariables = []string{`MONITOR_BINDING={"container_id":"` + monitorID + `","owner_public_key":"owner"}`}
	_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"work"}) })
	require.NoError(t, err)
	require.Equal(t, 1, creates)
}
