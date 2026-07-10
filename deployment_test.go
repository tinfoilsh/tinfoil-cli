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

func TestContainerGroupMovesRepositoryDeployment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
			_, _ = io.WriteString(w, `[{"id":"container-1","name":"app-1","repo":"acme/app","deployment_id":"deployment-1"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/deployments":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app","group_order":4,"display_order":7,"instance_count":3,"ready_count":2,"failed_count":1}]`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/deployments/deployment-1/group":
			var body struct {
				GroupName    *string `json:"group_name"`
				GroupOrder   int32   `json:"group_order"`
				DisplayOrder int32   `json:"display_order"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.GroupName == nil || *body.GroupName != "production" {
				t.Fatalf("group_name = %v", body.GroupName)
			}
			if body.GroupOrder != 4 || body.DisplayOrder != 7 {
				t.Fatalf("orders = (%d, %d), want (4, 7)", body.GroupOrder, body.DisplayOrder)
			}
			_, _ = io.WriteString(w, `{"id":"deployment-1","repo":"acme/app","group_name":"production","group_order":4,"display_order":7}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureDeploymentCommandTest(t, server.URL)
	groupName = "production"

	output, err := captureTestStdout(func() error {
		return containerGroupCmd.RunE(containerGroupCmd, []string{"app-1"})
	})
	if err != nil {
		t.Fatalf("run group: %v", err)
	}
	var updated deploymentView
	if err := json.Unmarshal(output, &updated); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if updated.InstanceCount != 3 || updated.ReadyCount != 2 || updated.FailedCount != 1 {
		t.Fatalf(
			"counts = (%d, %d, %d), want (3, 2, 1)",
			updated.InstanceCount,
			updated.ReadyCount,
			updated.FailedCount,
		)
	}
}

func TestContainerCreateSetsDeploymentGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/containers":
			var body struct {
				Repo         string  `json:"repo"`
				GroupName    *string `json:"group_name"`
				GroupOrder   *int32  `json:"group_order"`
				DisplayOrder *int32  `json:"display_order"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Repo != "acme/app" {
				t.Fatalf("create body = %+v", body)
			}
			if body.GroupName != nil || body.GroupOrder != nil {
				t.Fatalf("legacy group fields were sent: %+v", body)
			}
			if body.DisplayOrder == nil || *body.DisplayOrder != 2 {
				t.Fatalf("display_order = %v, want 2", body.DisplayOrder)
			}
			_, _ = io.WriteString(w, `{"id":"container-1","name":"app-1","repo":"acme/app","deployment_id":"deployment-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/deployments":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app","display_order":7}]`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/deployments/deployment-1/group":
			var body struct {
				GroupName    *string `json:"group_name"`
				GroupOrder   int32   `json:"group_order"`
				DisplayOrder int32   `json:"display_order"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.GroupName == nil || *body.GroupName != "production" {
				t.Fatalf("group_name = %v", body.GroupName)
			}
			if body.GroupOrder != 4 || body.DisplayOrder != 7 {
				t.Fatalf("orders = (%d, %d), want (4, 7)", body.GroupOrder, body.DisplayOrder)
			}
			_, _ = io.WriteString(w, `{"id":"deployment-1","repo":"acme/app","group_name":"production","group_order":4,"display_order":7}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureDeploymentCommandTest(t, server.URL)
	createRepo = "acme/app"
	createTag = "v1.2.3"
	createGroupName = "production"
	createGroupOrder = 4
	createDisplayOrder = 2
	displayOrderFlag := containerCreateCmd.Flags().Lookup("display-order")
	previousDisplayOrderChanged := displayOrderFlag.Changed
	displayOrderFlag.Changed = true
	t.Cleanup(func() {
		displayOrderFlag.Changed = previousDisplayOrderChanged
	})

	if err := containerCreateCmd.RunE(containerCreateCmd, []string{"app-1"}); err != nil {
		t.Fatalf("run create: %v", err)
	}
}

func TestDeploymentUpdateUsesDeploymentEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/deployments":
			_, _ = io.WriteString(w, `[{"id":"deployment-1","repo":"acme/app"}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/deployments/deployment-1/update":
			var body struct {
				Tag         string   `json:"tag"`
				InstanceIDs []string `json:"instance_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Tag != "v1.2.3" {
				t.Fatalf("tag = %q", body.Tag)
			}
			if len(body.InstanceIDs) != 1 || body.InstanceIDs[0] != "container-1" {
				t.Fatalf("instance_ids = %v", body.InstanceIDs)
			}
			_, _ = io.WriteString(w, `{"results":[{"container_id":"container-1","name":"app-1","status":"updating"}]}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureDeploymentCommandTest(t, server.URL)
	deploymentUpdateTag = "v1.2.3"
	deploymentUpdateInstanceIDs = []string{"container-1"}

	if err := deploymentUpdateCmd.RunE(deploymentUpdateCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("run deployment update: %v", err)
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
	previousGroupName := groupName
	previousGroupUngroup := groupUngroup
	previousGroupOrder := groupOrder
	previousGroupDisplayOrder := groupDisplayOrder
	previousCreateRepo := createRepo
	previousCreateTag := createTag
	previousCreateGroupName := createGroupName
	previousCreateGroupOrder := createGroupOrder
	previousCreateDisplayOrder := createDisplayOrder
	previousUpdateTag := deploymentUpdateTag
	previousUpdateStaging := deploymentUpdateStaging
	previousUpdateInstanceIDs := deploymentUpdateInstanceIDs
	previousUseDebugFilter := useDebugFilter

	outputFormat = "json"
	deploymentSettingsDefaultStaging = ""
	groupName = ""
	groupUngroup = false
	groupOrder = 0
	groupDisplayOrder = 0
	createRepo = ""
	createTag = ""
	createGroupName = ""
	createGroupOrder = 0
	createDisplayOrder = 0
	deploymentUpdateTag = ""
	deploymentUpdateStaging = ""
	deploymentUpdateInstanceIDs = nil
	useDebugFilter = false

	t.Cleanup(func() {
		outputFormat = previousOutput
		deploymentSettingsDefaultStaging = previousSettingsDefaultStaging
		groupName = previousGroupName
		groupUngroup = previousGroupUngroup
		groupOrder = previousGroupOrder
		groupDisplayOrder = previousGroupDisplayOrder
		createRepo = previousCreateRepo
		createTag = previousCreateTag
		createGroupName = previousCreateGroupName
		createGroupOrder = previousCreateGroupOrder
		createDisplayOrder = previousCreateDisplayOrder
		deploymentUpdateTag = previousUpdateTag
		deploymentUpdateStaging = previousUpdateStaging
		deploymentUpdateInstanceIDs = previousUpdateInstanceIDs
		useDebugFilter = previousUseDebugFilter
	})
}

func captureTestStdout(run func() error) ([]byte, error) {
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	os.Stdout = writer
	runErr := run()
	closeErr := writer.Close()
	os.Stdout = previous
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if runErr != nil {
		return output, runErr
	}
	if closeErr != nil {
		return output, closeErr
	}
	return output, readErr
}
