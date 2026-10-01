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

func TestProjectOutputLabelsDeployingAndPreservesJSONField(t *testing.T) {
	deployment := projectView{
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
		{name: "get", run: func() error { return renderProject(deployment) }},
		{name: "list", run: func() error { return renderProjects([]projectView{deployment}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outputFormat = "table"
			output, err := captureTestStdout(tt.run)
			if err != nil {
				t.Fatalf("render human output: %v", err)
			}
			if strings.Contains(string(output), "In progress") || strings.Contains(string(output), "IN-PROGRESS") || strings.Contains(string(output), "Ready") {
				t.Fatalf("human output uses a label that is not a container status:\n%s", output)
			}
			wantLabel := "Deploying:       2"
			if tt.name == "list" {
				wantLabel = "DEPLOYING"
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
		if r.Method != http.MethodGet || r.URL.Path != "/api/containers/projects" {
			t.Fatalf("request = %s %s, want GET /api/containers/projects", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
	}))
	defer server.Close()

	client := &cpClient{baseURL: server.URL, http: server.Client()}
	for _, identifier := range []string{"deployment-1", "acme/app"} {
		deployment, err := resolveProject(client, identifier)
		if err != nil {
			t.Fatalf("resolveProject(%q): %v", identifier, err)
		}
		if deployment.ID != "deployment-1" {
			t.Fatalf("deployment ID = %q", deployment.ID)
		}
	}
}

func TestProjectSettingsUpdatesDefaultStaging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/containers/projects/deployment-1":
			var body struct {
				DefaultStaging bool `json:"hold_by_default"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !body.DefaultStaging {
				t.Fatal("hold_by_default = false, want true")
			}
			_, _ = io.WriteString(w, `{"id":"deployment-1","repo":"acme/app","hold_by_default":true}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureProjectCommandTest(t, server.URL)
	projectSettingsHoldByDefault = "true"

	if err := projectSettingsCmd.RunE(projectSettingsCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("run deployment settings: %v", err)
	}
}

func TestProjectUpdateMarkLatestReleaseRequestBodies(t *testing.T) {
	tests := []struct {
		name              string
		markLatestRelease string
		changed           bool
		wantErr           string
		wantRequests      int32
		wantBody          string
	}{
		{
			name:         "omitted",
			wantRequests: 4,
			wantBody:     `{"hold":true,"instance_ids":["container-1"],"tag":"v1.2.3"}`,
		},
		{
			name:              "true",
			markLatestRelease: "true",
			changed:           true,
			wantRequests:      4,
			wantBody:          `{"hold":true,"instance_ids":["container-1"],"mark_latest_release":true,"tag":"v1.2.3"}`,
		},
		{
			name:              "false",
			markLatestRelease: "false",
			changed:           true,
			wantRequests:      4,
			wantBody:          `{"hold":true,"instance_ids":["container-1"],"mark_latest_release":false,"tag":"v1.2.3"}`,
		},
		{
			name:              "relaxed",
			markLatestRelease: "no",
			changed:           true,
			wantRequests:      4,
			wantBody:          `{"hold":true,"instance_ids":["container-1"],"mark_latest_release":false,"tag":"v1.2.3"}`,
		},
		{
			name:              "invalid",
			markLatestRelease: "maybe",
			changed:           true,
			wantErr:           `--mark-latest: expected true/false, got "maybe"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
					_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers/projects/deployment-1/update/plan":
					writeTestUpdatePlan(t, w, r, "container-1", "deployment-1", updateStrategyBlueGreen)
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers/projects/deployment-1/update":
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

			configureProjectCommandTest(t, server.URL)
			projectUpdateTag = "v1.2.3"
			projectUpdateHold = "true"
			projectUpdateMarkLatestRelease = tt.markLatestRelease
			projectUpdateInstanceIDs = []string{"container-1"}
			projectUpdateCmd.Flags().Lookup("hold").Changed = true
			projectUpdateCmd.Flags().Lookup("mark-latest").Changed = tt.changed

			_, err := captureTestStdout(func() error {
				return projectUpdateCmd.RunE(projectUpdateCmd, []string{"acme/app"})
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("run project update: %v", err)
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

func TestLifecycleCommandSurface(t *testing.T) {
	if got, want := containerDeployCmd.Short, "Deploy a stopped or failed container"; got != want {
		t.Fatalf("container deploy help = %q, want %q", got, want)
	}
	if got, want := containerUpdateCmd.Short, "Update a running container to a new tag or configuration"; got != want {
		t.Fatalf("container update help = %q, want %q", got, want)
	}

	for _, command := range containerCmd.Commands() {
		switch command.Name() {
		case "group", "start", "relaunch", "accept":
			t.Fatalf("container %s command is registered", command.Name())
		}
		if command.Flags().Lookup("debug-mode") != nil {
			t.Fatalf("container %s has --debug-mode", command.Name())
		}
	}
	if len(containerUpdateCmd.Commands()) != 0 {
		t.Fatal("container update is a namespace instead of an action")
	}
	for _, name := range []string{"promote", "cancel"} {
		found := false
		for _, command := range containerCmd.Commands() {
			if command.Name() == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("container %s is not a top-level command", name)
		}
	}
	if containerUpdateCmd.Flags().Lookup("host") != nil {
		t.Fatal("container update has --host; hosts change through stop and deploy")
	}
	if containerUpdateCmd.Flags().Lookup("yes") == nil || projectUpdateCmd.Flags().Lookup("yes") == nil {
		t.Fatal("update commands are missing --yes for downtime confirmation")
	}
	if containerDeleteCmd.Flags().Lookup("yes") == nil {
		t.Fatal("container delete does not have --yes")
	}
	if rootCmd.PersistentFlags().Lookup("host") != nil || rootCmd.PersistentFlags().Lookup("enclave") == nil {
		t.Fatal("root enclave flag is not --enclave")
	}
	for _, command := range sandboxCmd.Commands() {
		switch command.Name() {
		case "destroy", "accept":
			t.Fatalf("sandbox %s command is registered", command.Name())
		}
	}
	for _, command := range volumeCmd.Commands() {
		if command.Name() == "update" {
			t.Fatal("volume update command is registered; renames use volume rename")
		}
	}
	for _, command := range projectCmd.Commands() {
		if command.Name() == "group" {
			t.Fatal("deployment group command is registered")
		}
	}

	if containerCreateCmd.Flags().Lookup("hold") != nil {
		t.Fatal("container create has --hold")
	}
	if containerDeployCmd.Flags().Lookup("hold") != nil {
		t.Fatal("container deploy has --hold")
	}
	if containerCreateCmd.Flags().Lookup("group-name") != nil || containerCreateCmd.Flags().Lookup("group-order") != nil {
		t.Fatal("container create has grouping flags")
	}
	if containerCreateCmd.Flags().Lookup("display-order") == nil {
		t.Fatal("container create does not have --display-order")
	}
	if containerUpdateCmd.Flags().Lookup("hold") == nil {
		t.Fatal("container update does not have --hold")
	}
	if projectUpdateCmd.Flags().Lookup("hold") == nil || projectUpdateCmd.Flags().Lookup("mark-latest") == nil {
		t.Fatal("project update is missing hold or mark-latest flags")
	}
	if projectSettingsCmd.Flags().Lookup("hold-by-default") == nil {
		t.Fatal("project settings does not have --hold-by-default")
	}
}

func TestProjectUpdateResultsFailForIncompleteUpdates(t *testing.T) {
	previousOutput := outputFormat
	t.Cleanup(func() {
		outputFormat = previousOutput
	})

	results := []projectInstanceResult{
		{Name: "app-1", Status: projectInstanceStatusFailed, Error: "host unavailable"},
		{Name: "app-2", Status: projectInstanceStatusSkipped, Error: "update already in progress"},
	}
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			outputFormat = format
			if err := renderProjectUpdateResults(results); err == nil {
				t.Fatal("expected incomplete deployment update error")
			}
		})
	}
}

func configureProjectCommandTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))

	previousOutput := outputFormat
	previousSettingsDefaultStaging := projectSettingsHoldByDefault
	previousUpdateTag := projectUpdateTag
	previousUpdateHold := projectUpdateHold
	previousUpdateMarkLatestRelease := projectUpdateMarkLatestRelease
	previousUpdateInstanceIDs := projectUpdateInstanceIDs
	previousUpdateYes := projectUpdateYes
	holdFlag := projectUpdateCmd.Flags().Lookup("hold")
	markLatestReleaseFlag := projectUpdateCmd.Flags().Lookup("mark-latest")
	previousHoldChanged := holdFlag.Changed
	previousMarkLatestReleaseChanged := markLatestReleaseFlag.Changed

	outputFormat = "json"
	projectSettingsHoldByDefault = ""
	projectUpdateTag = ""
	projectUpdateHold = ""
	projectUpdateMarkLatestRelease = ""
	projectUpdateInstanceIDs = nil
	projectUpdateYes = false
	holdFlag.Changed = false
	markLatestReleaseFlag.Changed = false

	t.Cleanup(func() {
		outputFormat = previousOutput
		projectSettingsHoldByDefault = previousSettingsDefaultStaging
		projectUpdateTag = previousUpdateTag
		projectUpdateHold = previousUpdateHold
		projectUpdateMarkLatestRelease = previousUpdateMarkLatestRelease
		projectUpdateInstanceIDs = previousUpdateInstanceIDs
		projectUpdateYes = previousUpdateYes
		holdFlag.Changed = previousHoldChanged
		markLatestReleaseFlag.Changed = previousMarkLatestReleaseChanged
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

func TestProjectUpdateRefusesHoldForReplaceInstances(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/containers/projects/deployment-1/update/plan":
			writeTestUpdatePlan(t, w, r, "gpu-1", "deployment-1", updateStrategyReplace)
		case r.Method == http.MethodPost:
			posts.Add(1)
			_, _ = io.WriteString(w, `{"results":[]}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureProjectCommandTest(t, server.URL)
	projectUpdateTag = "v2"
	projectUpdateHold = "true"
	projectUpdateCmd.Flags().Lookup("hold").Changed = true

	_, err := captureTestStdout(func() error {
		return projectUpdateCmd.RunE(projectUpdateCmd, []string{"acme/app"})
	})
	if err == nil || !strings.Contains(err.Error(), "holding for review is not available for app (strategy: replace") {
		t.Fatalf("error = %v", err)
	}
	if posts.Load() != 0 {
		t.Fatal("update must not be sent when staging is refused locally")
	}
}
