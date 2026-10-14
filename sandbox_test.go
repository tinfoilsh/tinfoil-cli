package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSandboxStartUsesSavedAliasWithoutMonitorLookup(t *testing.T) {
	for _, tc := range []struct {
		state   string
		restart bool
	}{
		{statusStopped, false}, {statusFailed, false},
		{statusStopped, true}, {statusFailed, true}, {statusRunning, true},
	} {
		t.Run(fmt.Sprintf("%s/restart=%t", tc.state, tc.restart), func(t *testing.T) {
			const monitorID = "11111111-1111-4111-8111-111111111111"
			row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Status: tc.state,
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
			_, err := startSandboxRow(client, row, tc.restart)
			require.ErrorContains(t, err, "test boot failure")
			require.EqualValues(t, 1, starts.Load())
			expected := []string{"/api/containers/work-id/deploy"}
			if tc.restart && tc.state == statusRunning {
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

func TestSandboxCommandsShareLifecycleAndHandleDeletedResources(t *testing.T) {
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo, Status: statusRunning}
	deleted, polls := false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers":
			if deleted {
				json.NewEncoder(w).Encode([]containerView{})
			} else {
				json.NewEncoder(w).Encode([]containerView{row})
			}
		case "GET /api/containers/" + row.ID:
			if row.Status == statusStopping {
				polls++
				row.Status = statusStopped
			}
			json.NewEncoder(w).Encode(row)
		case "POST /api/containers/" + row.ID + "/stop":
			row.Status = statusStopping
			json.NewEncoder(w).Encode(row)
		case "DELETE /api/containers/" + row.ID:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldInterval, oldYes, oldOutput := followInterval, sandboxYes, outputFormat
	followInterval, sandboxYes, outputFormat = time.Millisecond, true, "json"
	t.Cleanup(func() { followInterval, sandboxYes, outputFormat = oldInterval, oldYes, oldOutput })
	for _, state := range []string{statusCreated, statusDeploying, statusStarted, statusStopping} {
		row.Status = state
		output, err := captureTestStdout(func() error { return sandboxStatusCmd.RunE(sandboxStatusCmd, nil) })
		require.NoError(t, err)
		var listed []containerView
		require.NoError(t, json.Unmarshal([]byte(output), &listed))
		require.Equal(t, state, listed[0].Status)
	}
	row.Status = statusRunning
	_, err := captureTestStdout(func() error { return sandboxStopCmd.RunE(sandboxStopCmd, []string{row.ID}) })
	require.NoError(t, err)
	require.Equal(t, 1, polls)
	profile := filepath.Join(home, ".ssh", "tinfoil", "work.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(profile), 0700))
	require.NoError(t, os.WriteFile(profile, []byte("# tinfoil-resource: "+server.URL+"//owner/"+row.ID+"\n"), 0600))
	for range 2 {
		require.NoError(t, sandboxDeleteCmd.RunE(sandboxDeleteCmd, []string{row.Name}))
	}
	require.NoFileExists(t, profile)
}
