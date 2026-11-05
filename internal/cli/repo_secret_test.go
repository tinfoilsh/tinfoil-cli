package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepoSecretCommandsUseScopedEndpoints(t *testing.T) {
	commandState := newCommandFixture()

	type requestExpectation struct {
		method string
		path   string
		body   map[string]string
		result string
	}
	expectations := []requestExpectation{
		{
			method: http.MethodGet,
			path:   "/api/repositories/acme/app/secrets",
			result: `[{"id":"one","name":"DATABASE_URL","scope":"repo","updated_at":"2026-07-10T00:00:00Z"}]`,
		},
		{
			method: http.MethodGet,
			path:   "/api/repositories/acme/app/secrets/DATABASE_URL",
			result: `{"id":"one","name":"DATABASE_URL","scope":"repo","updated_at":"2026-07-10T00:00:00Z"}`,
		},
		{
			method: http.MethodPost,
			path:   "/api/repositories/acme/app/secrets",
			body:   map[string]string{"name": "DATABASE_URL", "value": "create-value"},
			result: `{"id":"one","name":"DATABASE_URL","scope":"repo"}`,
		},
		{
			method: http.MethodPut,
			path:   "/api/repositories/acme/app/secrets/DATABASE_URL",
			body:   map[string]string{"value": "update-value"},
			result: `{"id":"one","name":"DATABASE_URL","scope":"repo"}`,
		},
		{
			method: http.MethodDelete,
			path:   "/api/repositories/acme/app/secrets/DATABASE_URL",
			result: `{"message":"secret deleted"}`,
		},
	}
	requestIndex := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIndex >= len(expectations) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		expectation := expectations[requestIndex]
		requestIndex++
		if r.Method != expectation.method {
			t.Errorf("method = %s, want %s", r.Method, expectation.method)
		}
		if r.URL.Path != expectation.path {
			t.Errorf("path = %q, want %q", r.URL.Path, expectation.path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin_test" {
			t.Errorf("authorization = %q", got)
		}
		if expectation.body != nil {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			for key, want := range expectation.body {
				if body[key] != want {
					t.Errorf("body[%q] = %q, want %q", key, body[key], want)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, expectation.result)
	}))
	defer server.Close()

	configureRepoCommandTest(commandState, t, server.URL)
	configureRepoSecretValueTest(commandState, t)

	if err := commandState.repoSecretListCmd.RunE(commandState.repoSecretListCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("list repository secrets: %v", err)
	}
	if err := commandState.repoSecretGetCmd.RunE(commandState.repoSecretGetCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("get repository secret: %v", err)
	}
	commandState.secretValueOpts.secretValue = "create-value"
	commandState.repoSecretCreateCmd.Flags().Lookup("value").Changed = true
	if err := commandState.repoSecretCreateCmd.RunE(commandState.repoSecretCreateCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("create repository secret: %v", err)
	}
	commandState.secretValueOpts.secretValue = "update-value"
	commandState.repoSecretSetCmd.Flags().Lookup("value").Changed = true
	if err := commandState.repoSecretSetCmd.RunE(commandState.repoSecretSetCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("update repository secret: %v", err)
	}
	if err := commandState.repoSecretDeleteCmd.RunE(commandState.repoSecretDeleteCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("delete repository secret: %v", err)
	}
	if requestIndex != len(expectations) {
		t.Fatalf("received %d requests, want %d", requestIndex, len(expectations))
	}
}

func TestRepoSecretScopeAndPathEscaping(t *testing.T) {
	repository, err := parseRepository("acme/my app")
	if err != nil {
		t.Fatalf("parse repository: %v", err)
	}
	if got, want := repository.secretAPIPath("token/name"), "/api/repositories/acme/my%20app/secrets/token%2Fname"; got != want {
		t.Fatalf("secret path = %q, want %q", got, want)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"id":"one","name":"TOKEN","scope":"repo"}]`)
	}))
	defer server.Close()
	client := &cpClient{baseURL: server.URL, http: server.Client()}
	secrets, err := listSecrets(client, "/api/repositories/acme/app/secrets")
	if err != nil {
		t.Fatalf("list repository secrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Scope != "repo" {
		t.Fatalf("scope = %#v, want repo", secrets)
	}
}

func TestRepoSecretRejectsInvalidRepository(t *testing.T) {
	commandState := newCommandFixture()

	if err := commandState.repoSecretListCmd.RunE(commandState.repoSecretListCmd, []string{"missing-owner"}); err == nil {
		t.Fatal("expected repository validation error")
	}
}

func configureRepoSecretValueTest(commandState *commandFixture, t *testing.T) {
	t.Helper()
	previousValue := commandState.secretValueOpts.secretValue
	previousFile := commandState.secretValueOpts.secretValueFile
	createValueChanged := commandState.repoSecretCreateCmd.Flags().Lookup("value").Changed
	createFileChanged := commandState.repoSecretCreateCmd.Flags().Lookup("value-file").Changed
	setValueChanged := commandState.repoSecretSetCmd.Flags().Lookup("value").Changed
	setFileChanged := commandState.repoSecretSetCmd.Flags().Lookup("value-file").Changed
	commandState.secretValueOpts.secretValue = ""
	commandState.secretValueOpts.secretValueFile = ""
	t.Cleanup(func() {
		commandState.secretValueOpts.secretValue = previousValue
		commandState.secretValueOpts.secretValueFile = previousFile
		commandState.repoSecretCreateCmd.Flags().Lookup("value").Changed = createValueChanged
		commandState.repoSecretCreateCmd.Flags().Lookup("value-file").Changed = createFileChanged
		commandState.repoSecretSetCmd.Flags().Lookup("value").Changed = setValueChanged
		commandState.repoSecretSetCmd.Flags().Lookup("value-file").Changed = setFileChanged
	})
}
