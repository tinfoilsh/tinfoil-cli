package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeploymentOutputLabelsInProgressAndPreservesJSONField(t *testing.T) {
	deployment := deploymentView{
		ID:             "deployment-1",
		Repo:           "acme/app",
		InstanceCount:  4,
		DeployingCount: 2,
		FailedCount:    3,
	}

	previousOutput := outputFormat
	t.Cleanup(func() { outputFormat = previousOutput })

	for _, tt := range []struct {
		name string
		run  func() error
	}{
		{name: "get", run: func() error { return renderDeployment(deployment) }},
		{name: "list", run: func() error { return renderDeployments([]deploymentView{deployment}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outputFormat = "table"
			output, err := captureTestStdout(tt.run)
			if err != nil {
				t.Fatalf("render human output: %v", err)
			}
			if strings.Contains(string(output), "Deploying") || strings.Contains(string(output), "DEPLOYING") {
				t.Fatalf("human output uses deploying label:\n%s", output)
			}
			wantLabel := "In progress:     2"
			if tt.name == "list" {
				wantLabel = "IN-PROGRESS"
			}
			if !strings.Contains(string(output), wantLabel) {
				t.Fatalf("human output does not contain %q:\n%s", wantLabel, output)
			}
			if tt.name == "list" {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				failedColumn := strings.Index(lines[0], "FAILED")
				if failedColumn < 0 || len(lines) != 2 || len(lines[1]) <= failedColumn || lines[1][failedColumn] != '3' {
					t.Fatalf("deployment row does not align with widened header:\n%s", output)
				}
			}

			outputFormat = "json"
			output, err = captureTestStdout(tt.run)
			if err != nil {
				t.Fatalf("render JSON output: %v", err)
			}
			if !strings.Contains(string(output), `"deploying_count": 2`) {
				t.Fatalf("JSON output does not preserve deploying_count:\n%s", output)
			}
			if strings.Contains(string(output), "in_progress_count") {
				t.Fatalf("JSON output renamed deploying_count:\n%s", output)
			}
		})
	}
}

func TestResolveDeploymentMatchesIDAndRepository(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/deployments" {
			t.Fatalf("request = %s %s, want GET /api/deployments", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
	}))
	defer server.Close()

	client := &cpClient{baseURL: server.URL, http: server.Client()}
	for _, identifier := range []string{"deployment-1", "acme/app"} {
		deployment, err := resolveDeployment(client, identifier)
		if err != nil {
			t.Fatalf("resolveDeployment(%q): %v", identifier, err)
		}
		if deployment.ID != "deployment-1" {
			t.Fatalf("deployment ID = %q", deployment.ID)
		}
	}
}

func TestDeploymentSettingsUpdatesDefaultStaging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/deployments":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/deployments/deployment-1":
			var body struct {
				DefaultStaging bool `json:"default_staging"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !body.DefaultStaging {
				t.Fatal("default_staging = false, want true")
			}
			_, _ = io.WriteString(w, `{"id":"deployment-1","repo":"acme/app","default_staging":true}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureDeploymentCommandTest(t, server.URL)
	deploymentSettingsDefaultStaging = "true"

	if err := deploymentSettingsCmd.RunE(deploymentSettingsCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("run deployment settings: %v", err)
	}
}

func TestDeploymentUpdatePromoteReleaseRequestBodies(t *testing.T) {
	tests := []struct {
		name           string
		promoteRelease string
		changed        bool
		wantErr        string
		wantRequests   int32
		wantBody       string
	}{
		{
			name:    "omitted",
			wantErr: "--promote-release is required; pass --promote-release=true or --promote-release=false",
		},
		{
			name:           "true",
			promoteRelease: "true",
			changed:        true,
			wantRequests:   2,
			wantBody:       `{"instance_ids":["container-1"],"promote_release":true,"staging":true,"tag":"v1.2.3"}`,
		},
		{
			name:           "false",
			promoteRelease: "false",
			changed:        true,
			wantRequests:   2,
			wantBody:       `{"instance_ids":["container-1"],"promote_release":false,"staging":true,"tag":"v1.2.3"}`,
		},
		{
			name:           "invalid",
			promoteRelease: "yes",
			changed:        true,
			wantErr:        `--promote-release must be true or false, got "yes"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/deployments":
					_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
				case r.Method == http.MethodPost && r.URL.Path == "/api/deployments/deployment-1/update":
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatalf("read body: %v", err)
					}
					if string(body) != tt.wantBody {
						t.Fatalf("body = %s, want %s", body, tt.wantBody)
					}
					_, _ = io.WriteString(w, `{"results":[{"container_id":"container-1","name":"app-1","status":"updating"}]}`)
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			configureDeploymentCommandTest(t, server.URL)
			deploymentUpdateTag = "v1.2.3"
			deploymentUpdateStaging = "true"
			deploymentUpdatePromoteRelease = tt.promoteRelease
			deploymentUpdateInstanceIDs = []string{"container-1"}
			deploymentUpdateCmd.Flags().Lookup("staging").Changed = true
			deploymentUpdateCmd.Flags().Lookup("promote-release").Changed = tt.changed

			_, err := captureTestStdout(func() error {
				return deploymentUpdateCmd.RunE(deploymentUpdateCmd, []string{"acme/app"})
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("run deployment update: %v", err)
				}
			} else if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if got := requests.Load(); got != tt.wantRequests {
				t.Fatalf("requests = %d, want %d", got, tt.wantRequests)
			}
		})
	}
}

func TestV016CommandSurface(t *testing.T) {
	if got, want := containerRelaunchCmd.Short, "Redeploy a ready or failed container"; got != want {
		t.Fatalf("container relaunch help = %q, want %q", got, want)
	}

	for _, command := range containerCmd.Commands() {
		if command.Name() == "group" {
			t.Fatal("container group command is registered")
		}
	}
	for _, command := range deploymentCmd.Commands() {
		if command.Name() == "group" {
			t.Fatal("deployment group command is registered")
		}
	}

	if containerCreateCmd.Flags().Lookup("staging") != nil {
		t.Fatal("container create has --staging")
	}
	if containerStartCmd.Flags().Lookup("staging") != nil {
		t.Fatal("container start has --staging")
	}
	if containerCreateCmd.Flags().Lookup("group-name") != nil || containerCreateCmd.Flags().Lookup("group-order") != nil {
		t.Fatal("container create has grouping flags")
	}
	if containerCreateCmd.Flags().Lookup("display-order") == nil {
		t.Fatal("container create does not have --display-order")
	}
	if containerRelaunchCmd.Flags().Lookup("staging") == nil {
		t.Fatal("container relaunch does not have --staging")
	}
	if deploymentUpdateCmd.Flags().Lookup("staging") == nil || deploymentUpdateCmd.Flags().Lookup("promote-release") == nil {
		t.Fatal("deployment update is missing staging or promotion flags")
	}
	if deploymentSettingsCmd.Flags().Lookup("default-staging") == nil {
		t.Fatal("deployment settings does not have --default-staging")
	}
}

func TestDeploymentUpdateResultsFailForIncompleteUpdates(t *testing.T) {
	previousOutput := outputFormat
	t.Cleanup(func() {
		outputFormat = previousOutput
	})

	results := []deploymentInstanceResult{
		{Name: "app-1", Status: deploymentInstanceStatusFailed, Error: "host unavailable"},
		{Name: "app-2", Status: deploymentInstanceStatusSkipped, Error: "update already in progress"},
	}
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			outputFormat = format
			if err := renderDeploymentUpdateResults(results); err == nil {
				t.Fatal("expected incomplete deployment update error")
			}
		})
	}
}

func configureDeploymentCommandTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAPIKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))

	previousOutput := outputFormat
	previousSettingsDefaultStaging := deploymentSettingsDefaultStaging
	previousUpdateTag := deploymentUpdateTag
	previousUpdateStaging := deploymentUpdateStaging
	previousUpdatePromoteRelease := deploymentUpdatePromoteRelease
	previousUpdateInstanceIDs := deploymentUpdateInstanceIDs
	previousUseDebugFilter := useDebugFilter
	stagingFlag := deploymentUpdateCmd.Flags().Lookup("staging")
	promoteReleaseFlag := deploymentUpdateCmd.Flags().Lookup("promote-release")
	previousStagingChanged := stagingFlag.Changed
	previousPromoteReleaseChanged := promoteReleaseFlag.Changed

	outputFormat = "json"
	deploymentSettingsDefaultStaging = ""
	deploymentUpdateTag = ""
	deploymentUpdateStaging = ""
	deploymentUpdatePromoteRelease = ""
	deploymentUpdateInstanceIDs = nil
	useDebugFilter = false
	stagingFlag.Changed = false
	promoteReleaseFlag.Changed = false

	t.Cleanup(func() {
		outputFormat = previousOutput
		deploymentSettingsDefaultStaging = previousSettingsDefaultStaging
		deploymentUpdateTag = previousUpdateTag
		deploymentUpdateStaging = previousUpdateStaging
		deploymentUpdatePromoteRelease = previousUpdatePromoteRelease
		deploymentUpdateInstanceIDs = previousUpdateInstanceIDs
		useDebugFilter = previousUseDebugFilter
		stagingFlag.Changed = previousStagingChanged
		promoteReleaseFlag.Changed = previousPromoteReleaseChanged
	})
}

func TestCaptureTestStdoutRestoresStdoutAfterPanic(t *testing.T) {
	previous := os.Stdout
	didPanic := false

	func() {
		defer func() {
			didPanic = recover() != nil
		}()
		_, _ = captureTestStdout(func() error {
			panic("test panic")
		})
	}()

	if !didPanic {
		t.Fatal("captureTestStdout did not propagate panic")
	}
	if os.Stdout != previous {
		t.Fatal("captureTestStdout did not restore stdout after panic")
	}
}

func captureTestStdout(run func() error) ([]byte, error) {
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	defer writer.Close()
	os.Stdout = writer
	defer func() {
		os.Stdout = previous
	}()
	runErr := run()
	closeErr := writer.Close()
	output, readErr := io.ReadAll(reader)
	if runErr != nil {
		return output, runErr
	}
	if closeErr != nil {
		return output, closeErr
	}
	return output, readErr
}
