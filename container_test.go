package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
)

func TestContainerDetailIncludesPromoteRelease(t *testing.T) {
	previousOutput := outputFormat
	t.Cleanup(func() { outputFormat = previousOutput })

	for _, promoteRelease := range []bool{false, true} {
		t.Run(boolString(promoteRelease), func(t *testing.T) {
			var container containerView
			response := `{"promote_release":` + boolString(promoteRelease) + `}`
			if err := json.Unmarshal([]byte(response), &container); err != nil {
				t.Fatalf("decode container response: %v", err)
			}

			outputFormat = "table"
			output, err := captureTestStdout(func() error { return renderContainer(container) })
			if err != nil {
				t.Fatalf("render human output: %v", err)
			}
			want := "Promote:      " + boolString(promoteRelease)
			if !strings.Contains(string(output), want) {
				t.Fatalf("human output does not contain %q:\n%s", want, output)
			}

			outputFormat = "json"
			output, err = captureTestStdout(func() error { return renderContainer(container) })
			if err != nil {
				t.Fatalf("render JSON output: %v", err)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(output, &decoded); err != nil {
				t.Fatalf("decode JSON output: %v", err)
			}
			value, ok := decoded["promote_release"]
			if !ok {
				t.Fatalf("JSON output is missing promote_release:\n%s", output)
			}
			if got, want := string(value), boolString(promoteRelease); got != want {
				t.Fatalf("promote_release JSON value = %s, want boolean %s", got, want)
			}
		})
	}
}

func TestContainerCommandsRequirePromoteRelease(t *testing.T) {
	const containerID = "61bd4a3e-5b48-4320-9215-0c7a7f974979"

	commands := []struct {
		name         string
		command      *cobra.Command
		path         string
		wantRequests int32
		wantBody     func(bool) string
		setValue     func(string)
		run          func() error
	}{
		{
			name:         "create",
			command:      containerCreateCmd,
			path:         "/api/containers",
			wantRequests: 1,
			wantBody: func(value bool) string {
				return `{"name":"app","promote_release":` + boolString(value) + `,"repo":"acme/app","tag":"v1.2.3"}`
			},
			setValue: func(value string) { createPromoteRelease = value },
			run:      func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) },
		},
		{
			name:         "start",
			command:      containerStartCmd,
			path:         "/api/containers/" + containerID + "/start",
			wantRequests: 2,
			wantBody: func(value bool) string {
				return `{"promote_release":` + boolString(value) + `}`
			},
			setValue: func(value string) { startPromoteRelease = value },
			run:      func() error { return containerStartCmd.RunE(containerStartCmd, []string{containerID}) },
		},
		{
			name:         "relaunch",
			command:      containerRelaunchCmd,
			path:         "/api/containers/" + containerID + "/relaunch",
			wantRequests: 2,
			wantBody: func(value bool) string {
				return `{"promote_release":` + boolString(value) + `}`
			},
			setValue: func(value string) { relaunchPromoteRelease = value },
			run:      func() error { return containerRelaunchCmd.RunE(containerRelaunchCmd, []string{containerID}) },
		},
	}
	values := []struct {
		name         string
		value        string
		changed      bool
		wantValue    bool
		wantErr      string
		localFailure bool
	}{
		{
			name:         "omitted",
			wantErr:      "--promote-release is required; pass --promote-release=true or --promote-release=false",
			localFailure: true,
		},
		{name: "true", value: "true", changed: true, wantValue: true},
		{name: "false", value: "false", changed: true},
		{
			name:         "invalid",
			value:        "yes",
			changed:      true,
			wantErr:      `--promote-release must be true or false, got "yes"`,
			localFailure: true,
		},
	}

	for _, command := range commands {
		for _, value := range values {
			t.Run(command.name+"/"+value.name, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+containerID:
						_, _ = io.WriteString(w, `{"id":"`+containerID+`","name":"app"}`)
					case r.Method == http.MethodPost && r.URL.Path == command.path:
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read body: %v", err)
							return
						}
						if got, want := string(body), command.wantBody(value.wantValue); got != want {
							t.Errorf("body = %s, want %s", got, want)
						}
						_, _ = io.WriteString(w, `{}`)
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
				}))
				defer server.Close()

				configureContainerPromotionTest(t, server.URL)
				command.setValue(value.value)
				command.command.Flags().Lookup("promote-release").Changed = value.changed

				_, err := captureTestStdout(command.run)
				if value.wantErr == "" {
					if err != nil {
						t.Fatalf("run command: %v", err)
					}
				} else if err == nil || err.Error() != value.wantErr {
					t.Fatalf("error = %v, want %q", err, value.wantErr)
				}

				wantRequests := command.wantRequests
				if value.localFailure {
					wantRequests = 0
				}
				if got := requests.Load(); got != wantRequests {
					t.Fatalf("requests = %d, want %d", got, wantRequests)
				}
			})
		}
	}
}

func TestPromoteReleaseFlagsRequireValues(t *testing.T) {
	for _, command := range []*cobra.Command{
		containerCreateCmd,
		containerStartCmd,
		containerRelaunchCmd,
		deploymentUpdateCmd,
	} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			if got := command.Flags().Lookup("promote-release").NoOptDefVal; got != "" {
				t.Fatalf("NoOptDefVal = %q, want empty", got)
			}
		})
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func configureContainerPromotionTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAPIKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	for command, names := range map[*cobra.Command][]string{
		containerCreateCmd:   {"display-order", "promote-release"},
		containerStartCmd:    {"tag", "variable", "secret", "ssh-key", "debug", "promote-release", "custom-domain", "host"},
		containerRelaunchCmd: {"tag", "variable", "secret", "ssh-key", "debug", "staging", "promote-release", "custom-domain", "host"},
	} {
		for _, name := range names {
			flag := command.Flags().Lookup(name)
			previousChanged := flag.Changed
			flag.Changed = false
			t.Cleanup(func() {
				flag.Changed = previousChanged
			})
		}
	}

	previousOutput := outputFormat
	previousCreateRepo, previousCreateTag := createRepo, createTag
	previousCreatePromoteRelease := createPromoteRelease
	previousCreateDebug, previousCreateDisableCC := createDebug, createDisableCC
	previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys := createVariables, createSecrets, createSSHKeys
	previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID := createCustomDomain, createHost, createReplaceID
	previousCreateDisplayOrder := createDisplayOrder
	previousStartTag, previousStartDebug := startTag, startDebug
	previousStartPromoteRelease := startPromoteRelease
	previousStartVariables, previousStartSecrets, previousStartSSHKeys := startVariables, startSecrets, startSSHKeys
	previousStartCustomDomain, previousStartHost := startCustomDomain, startHost
	previousRelaunchTag, previousRelaunchDebug := relaunchTag, relaunchDebug
	previousRelaunchStaging, previousRelaunchPromoteRelease := relaunchStaging, relaunchPromoteRelease
	previousRelaunchVariables, previousRelaunchSecrets, previousRelaunchSSHKeys := relaunchVariables, relaunchSecrets, relaunchSSHKeys
	previousRelaunchCustomDomain, previousRelaunchHost := relaunchCustomDomain, relaunchHost

	outputFormat = "json"
	createRepo, createTag, createPromoteRelease = "acme/app", "v1.2.3", ""
	createDebug, createDisableCC = false, false
	createVariables, createSecrets, createSSHKeys = nil, nil, nil
	createCustomDomain, createHost, createReplaceID = "", "", ""
	createDisplayOrder = 0
	startTag, startDebug, startPromoteRelease = "", "", ""
	startVariables, startSecrets, startSSHKeys = nil, nil, nil
	startCustomDomain, startHost = "", ""
	relaunchTag, relaunchDebug, relaunchStaging, relaunchPromoteRelease = "", "", "", ""
	relaunchVariables, relaunchSecrets, relaunchSSHKeys = nil, nil, nil
	relaunchCustomDomain, relaunchHost = "", ""

	t.Cleanup(func() {
		outputFormat = previousOutput
		createRepo, createTag = previousCreateRepo, previousCreateTag
		createPromoteRelease = previousCreatePromoteRelease
		createDebug, createDisableCC = previousCreateDebug, previousCreateDisableCC
		createVariables, createSecrets, createSSHKeys = previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys
		createCustomDomain, createHost, createReplaceID = previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID
		createDisplayOrder = previousCreateDisplayOrder
		startTag, startDebug, startPromoteRelease = previousStartTag, previousStartDebug, previousStartPromoteRelease
		startVariables, startSecrets, startSSHKeys = previousStartVariables, previousStartSecrets, previousStartSSHKeys
		startCustomDomain, startHost = previousStartCustomDomain, previousStartHost
		relaunchTag, relaunchDebug = previousRelaunchTag, previousRelaunchDebug
		relaunchStaging, relaunchPromoteRelease = previousRelaunchStaging, previousRelaunchPromoteRelease
		relaunchVariables, relaunchSecrets, relaunchSSHKeys = previousRelaunchVariables, previousRelaunchSecrets, previousRelaunchSSHKeys
		relaunchCustomDomain, relaunchHost = previousRelaunchCustomDomain, previousRelaunchHost
	})
}
