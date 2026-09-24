package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhoamiIdentityAndCredentialSource(t *testing.T) {
	for _, source := range []string{"file", envAdminKey, envAPIKey} {
		for _, personal := range []bool{false, true} {
			t.Run(source+"/personal="+boolText(personal), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/api/auth/context" || r.Header.Get("Authorization") != "Bearer admin_identity_secret" {
						t.Errorf("unexpected identity request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if personal {
						io.WriteString(w, `{"context_type":"personal","organization":null,"user_id":"user_1"}`)
					} else {
						io.WriteString(w, `{"context_type":"organization","organization":{"id":"org_1"},"user_id":"user_1"}`)
					}
				}))
				defer server.Close()
				t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
				t.Setenv(envCPURL, server.URL)
				t.Setenv(envAdminKey, "")
				t.Setenv(envAPIKey, "tk_ignored")
				if source == "file" {
					if _, err := saveConfig(cliConfig{APIKey: "admin_identity_secret", ControlplaneURL: server.URL}); err != nil {
						t.Fatal(err)
					}
				} else {
					t.Setenv(source, "admin_identity_secret")
				}
				out, err := captureTestStdout(func() error { return whoamiCmd.RunE(whoamiCmd, nil) })
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{source, "user_1", "Effective login", "admin_id…cret"} {
					if !strings.Contains(string(out), want) {
						t.Fatalf("missing %q: %s", want, out)
					}
				}
				if strings.Contains(string(out), "admin_identity_secret") || strings.Contains(string(out), "Organization name") {
					t.Fatalf("unexpected identity output: %s", out)
				}
				if personal != strings.Contains(string(out), "Context: personal") {
					t.Fatalf("wrong context: %s", out)
				}
			})
		}
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestLoginReportsSavedAndEffectiveIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/context" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		id := "org_saved"
		if r.Header.Get("Authorization") == "Bearer admin_environment_secret" {
			id = "org_effective"
		}
		io.WriteString(w, `{"context_type":"organization","organization":{"id":"`+id+`","name":"Example"},"user_id":"user_1"}`)
	}))
	defer server.Close()
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_environment_secret")
	t.Setenv(envAPIKey, "")
	keyFlag := loginCmd.Flags().Lookup("api-key")
	oldValue, oldChanged := keyFlag.Value.String(), keyFlag.Changed
	t.Cleanup(func() { _ = keyFlag.Value.Set(oldValue); keyFlag.Changed = oldChanged })
	if err := loginCmd.Flags().Set("api-key", "admin_saved_secret"); err != nil {
		t.Fatal(err)
	}
	var stdout []byte
	warning, err := captureTestStderr(func() error {
		var err error
		stdout, err = captureTestStdout(func() error { return loginCmd.RunE(loginCmd, nil) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(stdout), "Effective login:")
	if len(parts) != 2 || !strings.Contains(parts[0], "org_saved") || !strings.Contains(parts[1], "org_effective") || strings.Contains(parts[1], "org_saved") {
		t.Fatalf("wrong saved/effective identity: %s", stdout)
	}
	if !strings.Contains(string(warning), "WARNING: environment overrides") {
		t.Fatalf("missing warning: %s", warning)
	}
	warning, err = captureTestStderr(func() error {
		_, err := captureTestStdout(func() error { return logoutCmd.RunE(logoutCmd, nil) })
		return err
	})
	if err != nil || !strings.Contains(string(warning), envAdminKey+" is still active") {
		t.Fatalf("logout warning=%s err=%v", warning, err)
	}
}

func TestIdentityRejectsInvalidAndUnauthorizedResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"context_type":"organization","organization":null}`, `{"context_type":"personal","organization":{"id":"org_wrong"},"user_id":"user_1"}`, `unauthorized`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body == "unauthorized" {
					w.WriteHeader(http.StatusUnauthorized)
				}
				io.WriteString(w, body)
			}))
			defer server.Close()
			if _, err := authenticatedContext(cliConfig{ControlplaneURL: server.URL}); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}
