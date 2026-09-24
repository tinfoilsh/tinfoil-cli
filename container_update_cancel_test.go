package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerUpdateCancelRollbackLatest(t *testing.T) {
	const (
		containerID   = "61bd4a3e-5b48-4320-9215-0c7a7f974979"
		containerName = "app"
		cancelPath    = "/api/containers/" + containerID + "/update/cancel"
		plainOutput   = "Cancelled in-progress update on app\n"
		rollbackBody  = `{"rollback_latest":true}`
		unconfirmed   = "update cancellation may have completed, but the controlplane did not confirm latest release restoration"
	)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	flag := containerUpdateCancelCmd.Flags().Lookup("rollback-latest")
	previousValue, previousChanged := cancelRollbackLatest, flag.Changed
	previousDebugFilter, previousStderr := useDebugFilter, rootCmd.ErrOrStderr()
	rootCmd.SetErr(io.Discard)
	t.Cleanup(func() {
		cancelRollbackLatest, flag.Changed = previousValue, previousChanged
		useDebugFilter = previousDebugFilter
		rootCmd.SetArgs(nil)
		rootCmd.SetErr(previousStderr)
	})

	tests := []struct {
		name         string
		args         []string
		wantBody     string
		status       int
		responseBody string
		wantOutput   string
		wantErr      string
	}{
		{
			name: "omitted preserves cancel", args: []string{containerID},
			status: http.StatusNoContent, wantOutput: plainOutput,
		},
		{
			name: "true by name", args: []string{containerName, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK,
			responseBody: `{"rollback_latest":true,"tag":"v1.2.2","extra":"ignored"}`,
			wantOutput:   "Canceled in-progress update on app; latest release restoration to v1.2.2 requested\n",
		},
		{
			name: "explicit false preserves cancel", args: []string{containerID, "--rollback-latest=false"},
			status: http.StatusNoContent, wantOutput: plainOutput,
		},
		{
			name: "cancel rejected", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusConflict,
			responseBody: `{"error":"update cannot be canceled"}`, wantErr: "update cannot be canceled",
		},
		{
			name: "restoration failed", args: []string{containerName, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusInternalServerError,
			responseBody: `{"error":"latest restoration failed"}`, wantErr: "latest restoration failed",
		},
		{
			name: "old server ignored rollback", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusNoContent, wantErr: unconfirmed,
		},
		{
			name: "missing acknowledgment", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK, responseBody: `{}`, wantErr: unconfirmed,
		},
		{
			name: "unexpected acknowledgment status", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusAccepted,
			responseBody: `{"rollback_latest":true,"tag":"v1.2.3"}`, wantErr: unconfirmed,
		},
		{
			name: "restoration not acknowledged", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK,
			responseBody: `{"rollback_latest":false,"tag":"v1.2.3"}`, wantErr: unconfirmed,
		},
		{
			name: "missing tag", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK,
			responseBody: `{"rollback_latest":true}`, wantErr: unconfirmed,
		},
		{
			name: "blank tag", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK,
			responseBody: `{"rollback_latest":true,"tag":" "}`, wantErr: unconfirmed,
		},
		{
			name: "invalid JSON", args: []string{containerID, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusOK, responseBody: `{`, wantErr: unconfirmed,
		},
		{
			name: "tag as flag value", args: []string{containerName, "--rollback-latest=v1.2.3"},
			wantErr: "invalid argument",
		},
		{
			name: "tag as positional argument", args: []string{containerName, "--rollback-latest", "v1.2.3"},
			wantErr: "accepts 1 arg(s), received 2",
		},
		{
			name: "tag flag", args: []string{containerName, "--rollback-latest", "--tag", "v1.2.3"},
			wantErr: "unknown flag: --tag",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cancelRollbackLatest, flag.Changed = false, false
			var lookups, cancellations atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				container := containerView{ID: containerID, Name: containerName, CurrentTag: "v1.2.3", UpdateTag: "v1.2.4"}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+containerID:
					lookups.Add(1)
					_ = json.NewEncoder(w).Encode(container)
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
					lookups.Add(1)
					_ = json.NewEncoder(w).Encode([]containerView{container})
				case r.Method == http.MethodPost && r.URL.Path == cancelPath:
					cancellations.Add(1)
					body, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					assert.Equal(t, tt.wantBody, string(body), "cancel body")
					wantContentType := ""
					if tt.wantBody != "" {
						wantContentType = "application/json"
					}
					assert.Equal(t, wantContentType, r.Header.Get("Content-Type"))
					w.WriteHeader(tt.status)
					_, _ = io.WriteString(w, tt.responseBody)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			t.Setenv(envCPURL, server.URL)

			rootCmd.SetArgs(append([]string{"container", "update", "cancel"}, tt.args...))
			output, err := captureTestStdout(rootCmd.Execute)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantOutput, string(output))
			wantRequests := int32(1)
			if tt.status == 0 {
				wantRequests = 0
			}
			assert.Equal(t, wantRequests, lookups.Load(), "lookups")
			assert.Equal(t, wantRequests, cancellations.Load(), "cancellations")
		})
	}
}
