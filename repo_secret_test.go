package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepoSecretCommandsUseScopedEndpoints(t *testing.T) {
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

	configureRepoCommandTest(t, server.URL)
	configureRepoSecretValueTest(t)

	if err := repoSecretListCmd.RunE(repoSecretListCmd, []string{"acme/app"}); err != nil {
		t.Fatalf("list repository secrets: %v", err)
	}
	if err := repoSecretGetCmd.RunE(repoSecretGetCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("get repository secret: %v", err)
	}
	secretValue = "create-value"
	repoSecretCreateCmd.Flags().Lookup("value").Changed = true
	if err := repoSecretCreateCmd.RunE(repoSecretCreateCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("create repository secret: %v", err)
	}
	secretValue = "update-value"
	repoSecretSetCmd.Flags().Lookup("value").Changed = true
	if err := repoSecretSetCmd.RunE(repoSecretSetCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
		t.Fatalf("update repository secret: %v", err)
	}
	if err := repoSecretDeleteCmd.RunE(repoSecretDeleteCmd, []string{"acme/app", "DATABASE_URL"}); err != nil {
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
	if err := repoSecretListCmd.RunE(repoSecretListCmd, []string{"missing-owner"}); err == nil {
		t.Fatal("expected repository validation error")
	}
}

func configureRepoSecretValueTest(t *testing.T) {
	t.Helper()
	previousValue := secretValue
	previousFile := secretValueFile
	createValueChanged := repoSecretCreateCmd.Flags().Lookup("value").Changed
	createFileChanged := repoSecretCreateCmd.Flags().Lookup("value-file").Changed
	setValueChanged := repoSecretSetCmd.Flags().Lookup("value").Changed
	setFileChanged := repoSecretSetCmd.Flags().Lookup("value-file").Changed
	secretValue = ""
	secretValueFile = ""
	t.Cleanup(func() {
		secretValue = previousValue
		secretValueFile = previousFile
		repoSecretCreateCmd.Flags().Lookup("value").Changed = createValueChanged
		repoSecretCreateCmd.Flags().Lookup("value-file").Changed = createFileChanged
		repoSecretSetCmd.Flags().Lookup("value").Changed = setValueChanged
		repoSecretSetCmd.Flags().Lookup("value-file").Changed = setFileChanged
	})
}
