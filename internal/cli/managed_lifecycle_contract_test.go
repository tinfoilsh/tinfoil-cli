package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMonitorDeletionPreservesRemoteAndLocalFailureOrdering(t *testing.T) {
	const sandboxID = "11111111-1111-4111-8111-111111111111"
	for _, test := range []struct {
		name          string
		remoteStatus  int
		brokenProfile bool
		wantError     string
	}{
		{"remote failure", http.StatusServiceUnavailable, false, "temporarily unavailable"},
		{"local cleanup failure", http.StatusNoContent, true, "deleted Monitor mon and its sandboxes work, but"},
	} {
		t.Run(test.name, func(t *testing.T) {
			monitor := containerView{ID: testContainerID, Name: "mon", Repo: monitorRepo, ClerkUserID: "owner"}
			policy := sandboxNetworkPolicy(monitor.ID)
			sandbox := containerView{ID: sandboxID, Name: "work", Repo: defaultSandboxRepo, ClerkUserID: "owner", NetworkPolicy: &policy}
			deleted := false
			managedTestAPI(newCommandFixture(), t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /api/auth/context":
					json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
				case "GET /api/containers/" + monitor.ID:
					json.NewEncoder(w).Encode(monitor)
				case "GET /api/containers":
					json.NewEncoder(w).Encode([]containerView{sandbox})
				case "DELETE /api/monitors/" + monitor.ID:
					deleted = true
					w.WriteHeader(test.remoteStatus)
					if test.remoteStatus != http.StatusNoContent {
						w.Write([]byte(`{"error":"temporarily unavailable"}`))
					}
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			})
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			profiles := filepath.Join(home, ".ssh", "tinfoil")
			require.NoError(t, os.MkdirAll(profiles, storageDirMode))
			profile := filepath.Join(profiles, sandbox.Name+".conf")
			marker := []byte("# tinfoil-resource: " + os.Getenv(envCPURL) + "//owner/" + sandbox.ID + "\n")
			if test.brokenProfile {
				require.NoError(t, os.Mkdir(profile, storageDirMode))
			} else {
				require.NoError(t, os.WriteFile(profile, marker, storageFileMode))
			}
			pins := filepath.Join(profiles, sandbox.Name+".known_hosts")
			require.NoError(t, os.WriteFile(pins, []byte("saved pin\n"), storageFileMode))
			var out, diagnostic bytes.Buffer
			cmd := newMonitorDeleteCmd(testScopeClient)
			cmd.SetOut(&out)
			cmd.SetErr(&diagnostic)
			require.NoError(t, cmd.Flags().Set("yes", "true"))

			err := cmd.RunE(cmd, []string{monitor.ID})
			require.ErrorContains(t, err, test.wantError)
			require.True(t, deleted)
			require.Empty(t, out.String())
			retainedPins, err := os.ReadFile(pins)
			require.NoError(t, err)
			require.Equal(t, "saved pin\n", string(retainedPins))
			if !test.brokenProfile {
				retained, err := os.ReadFile(profile)
				require.NoError(t, err)
				require.Equal(t, marker, retained)
			}
		})
	}
}

func TestMonitorDeletionWithoutConfirmationDoesNotMutate(t *testing.T) {
	monitor := containerView{ID: testContainerID, Name: "mon", Repo: monitorRepo, ClerkUserID: "owner"}
	mutations := 0
	managedTestAPI(newCommandFixture(), t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers/" + monitor.ID:
			json.NewEncoder(w).Encode(monitor)
		case "GET /api/containers":
			json.NewEncoder(w).Encode([]containerView{})
		default:
			mutations++
			http.Error(w, "unexpected mutation", http.StatusInternalServerError)
		}
	})
	input, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { input.Close() })
	previous := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previous })
	var out, diagnostic bytes.Buffer
	cmd := newMonitorDeleteCmd(testScopeClient)
	cmd.SetOut(&out)
	cmd.SetErr(&diagnostic)

	require.ErrorContains(t, cmd.RunE(cmd, []string{monitor.ID}), "--yes")
	require.Zero(t, mutations)
	require.Empty(t, out.String())
	require.Contains(t, diagnostic.String(), "permanently deletes the Monitor and all of its data")
}
