package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
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
			responseBody: `{"error":"update cannot be canceled"}`,
		},
		{
			name: "restoration failed", args: []string{containerName, "--rollback-latest"},
			wantBody: rollbackBody, status: http.StatusInternalServerError,
			responseBody: `{"error":"latest restoration failed"}`,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					if err != nil {
						t.Errorf("read cancel body: %v", err)
					}
					if string(body) != tt.wantBody {
						t.Errorf("cancel body = %q, want %q", body, tt.wantBody)
					}
					wantContentType := ""
					if tt.wantBody != "" {
						wantContentType = "application/json"
					}
					if got := r.Header.Get("Content-Type"); got != wantContentType {
						t.Errorf("Content-Type = %q, want %q", got, wantContentType)
					}
					w.WriteHeader(tt.status)
					_, _ = io.WriteString(w, tt.responseBody)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			configureCancelCommandTest(t, server.URL)

			output, err := runCancelCommandTest(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
			} else if tt.status == http.StatusNoContent || tt.status == http.StatusOK {
				if err != nil {
					t.Fatalf("cancel command: %v", err)
				}
			} else {
				var apiErr *cpError
				if !errors.As(err, &apiErr) || apiErr.Status != tt.status || apiErr.Message == "" {
					t.Fatalf("error = %v, want API error with status %d and message", err, tt.status)
				}
			}
			if string(output) != tt.wantOutput {
				t.Fatalf("output = %q, want %q", output, tt.wantOutput)
			}
			if lookups.Load() != 1 || cancellations.Load() != 1 {
				t.Fatalf("requests: %d lookups, %d cancellations; want one each", lookups.Load(), cancellations.Load())
			}
		})
	}
}

func TestContainerUpdateCancelRejectsTagArguments(t *testing.T) {
	for _, args := range [][]string{
		{"app", "--rollback-latest=v1.2.3"},
		{"app", "--rollback-latest", "v1.2.3"},
		{"app", "--rollback-latest", "--tag", "v1.2.3"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			configureCancelCommandTest(t, server.URL)
			output, err := runCancelCommandTest(args)
			if err == nil || len(output) != 0 || requests.Load() != 0 {
				t.Fatalf("invalid arguments reached cancel: error=%v output=%q requests=%d", err, output, requests.Load())
			}
		})
	}
}

func configureCancelCommandTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	flag := containerUpdateCancelCmd.Flags().Lookup("rollback-latest")
	previousValue, previousChanged := cancelRollbackLatest, flag.Changed
	previousDebugFilter := useDebugFilter
	cancelRollbackLatest, flag.Changed = false, false
	t.Cleanup(func() {
		cancelRollbackLatest, flag.Changed = previousValue, previousChanged
		useDebugFilter = previousDebugFilter
	})
}

func runCancelCommandTest(args []string) ([]byte, error) {
	cmd := containerUpdateCancelCmd
	if err := cmd.ParseFlags(args); err != nil {
		return nil, err
	}
	args = cmd.Flags().Args()
	if err := cmd.Args(cmd, args); err != nil {
		return nil, err
	}
	if err := cmd.PreRunE(cmd, args); err != nil {
		return nil, err
	}
	return captureTestStdout(func() error { return cmd.RunE(cmd, args) })
}
