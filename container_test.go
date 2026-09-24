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

func TestContainerDetailIncludesMarkLatestRelease(t *testing.T) {
	previousOutput := outputFormat
	t.Cleanup(func() { outputFormat = previousOutput })

	for _, tt := range []struct {
		name     string
		response string
		want     string
	}{
		{name: "true", response: `{"mark_latest_release":true}`, want: "true"},
		{name: "false", response: `{"mark_latest_release":false}`, want: "false"},
		{name: "omitted", response: `{}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var container containerView
			if err := json.Unmarshal([]byte(tt.response), &container); err != nil {
				t.Fatalf("decode container response: %v", err)
			}

			outputFormat = "table"
			output, err := captureTestStdout(func() error { return renderContainer(container) })
			if err != nil {
				t.Fatalf("render human output: %v", err)
			}
			markLatestLine := "Mark latest:  " + tt.want
			if tt.want != "" && !strings.Contains(string(output), markLatestLine) {
				t.Fatalf("human output does not contain %q:\n%s", markLatestLine, output)
			}
			if tt.want == "" && strings.Contains(string(output), "Mark latest:") {
				t.Fatalf("human output includes promotion value for omitted field:\n%s", output)
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
			value, ok := decoded["mark_latest_release"]
			if tt.want != "" && !ok {
				t.Fatalf("JSON output is missing mark_latest_release:\n%s", output)
			}
			if tt.want == "" && ok {
				t.Fatalf("JSON output includes promote_release for omitted field:\n%s", output)
			}
			if got, want := string(value), tt.want; got != want {
				t.Fatalf("promote_release JSON value = %s, want boolean %s", got, want)
			}
		})
	}
}

func TestContainerCommandsMarkLatestReleaseRequestBodies(t *testing.T) {
	const containerID = "61bd4a3e-5b48-4320-9215-0c7a7f974979"

	commands := []struct {
		name         string
		command      *cobra.Command
		path         string
		wantRequests int32
		wantBody     func(string) string
		setValue     func(string)
		run          func() error
	}{
		{
			name:         "create",
			command:      containerCreateCmd,
			path:         "/api/containers",
			wantRequests: 2,
			wantBody: func(promote string) string {
				return `{` + promote + `"name":"app","repo":"acme/app","tag":"v1.2.3"}`
			},
			setValue: func(value string) { createMarkLatestRelease = value },
			run:      func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) },
		},
		{
			name:         "deploy",
			command:      containerDeployCmd,
			path:         "/api/containers/" + containerID + "/deploy",
			wantRequests: 2,
			wantBody: func(promote string) string {
				return `{` + strings.TrimSuffix(promote, ",") + `}`
			},
			setValue: func(value string) { deployMarkLatestRelease = value },
			run:      func() error { return containerDeployCmd.RunE(containerDeployCmd, []string{containerID}) },
		},
		{
			name:         "update",
			command:      containerUpdateCmd,
			path:         "/api/containers/" + containerID + "/update",
			wantRequests: 2,
			wantBody: func(promote string) string {
				return `{` + strings.TrimSuffix(promote, ",") + `}`
			},
			setValue: func(value string) { updateMarkLatestRelease = value },
			run:      func() error { return containerUpdateCmd.RunE(containerUpdateCmd, []string{containerID}) },
		},
	}
	// wantMarkLatest is the JSON fragment expected in the body, including its
	// trailing comma, or empty when the field must be omitted entirely.
	values := []struct {
		name           string
		value          string
		changed        bool
		wantMarkLatest string
		wantErr        string
		localFailure   bool
	}{
		{name: "omitted"},
		{name: "true", value: "true", changed: true, wantMarkLatest: `"mark_latest_release":true,`},
		{name: "false", value: "false", changed: true, wantMarkLatest: `"mark_latest_release":false,`},
		{name: "relaxed", value: "no", changed: true, wantMarkLatest: `"mark_latest_release":false,`},
		{
			name:         "invalid",
			value:        "maybe",
			changed:      true,
			wantErr:      `--mark-latest: expected true/false, got "maybe"`,
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
					case r.Method == http.MethodPost && r.URL.Path == "/api/containers/validate":
						_, _ = io.WriteString(w, `{"valid":true,"config":{}}`)
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+containerID:
						_, _ = io.WriteString(w, `{"id":"`+containerID+`","name":"app"}`)
					case r.Method == http.MethodPost && r.URL.Path == command.path:
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read body: %v", err)
							return
						}
						if got, want := string(body), command.wantBody(value.wantMarkLatest); got != want {
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
				command.command.Flags().Lookup("mark-latest").Changed = value.changed

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
		containerDeployCmd,
		containerUpdateCmd,
		projectUpdateCmd,
	} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			if got := command.Flags().Lookup("mark-latest").NoOptDefVal; got != "" {
				t.Fatalf("NoOptDefVal = %q, want empty", got)
			}
		})
	}
}

func configureContainerPromotionTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	for command, names := range map[*cobra.Command][]string{
		containerCreateCmd: {"display-order", "mark-latest", "volume"},
		containerDeployCmd: {"tag", "variable", "secret", "ssh-key", "debug", "mark-latest", "custom-domain", "host", "volume", "no-wait"},
		containerUpdateCmd: {"tag", "variable", "secret", "ssh-key", "debug", "hold", "mark-latest", "custom-domain", "yes", "no-wait"},
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

	previousOutput, previousNoWait := outputFormat, noWait
	previousCreateRepo, previousCreateTag := createRepo, createTag
	previousCreateMarkLatestRelease := createMarkLatestRelease
	previousCreateDebug, previousCreateDisableCC := createDebug, createDisableCC
	previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys := createVariables, createSecrets, createSSHKeys
	previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID := createCustomDomain, createHost, createReplaceID
	previousCreateDisplayOrder, previousCreateVolumes := createDisplayOrder, createVolumes
	previousDeployTag, previousDeployDebug := deployTag, deployDebug
	previousDeployMarkLatestRelease := deployMarkLatestRelease
	previousDeployVariables, previousDeploySecrets, previousDeploySSHKeys := deployVariables, deploySecrets, deploySSHKeys
	previousDeployCustomDomain, previousDeployHost, previousDeployVolumes := deployCustomDomain, deployHost, deployVolumes
	previousUpdateTag, previousUpdateDebug := updateTag, updateDebug
	previousUpdateHold, previousUpdateMarkLatestRelease := updateHold, updateMarkLatestRelease
	previousUpdateVariables, previousUpdateSecrets, previousUpdateSSHKeys := updateVariables, updateSecrets, updateSSHKeys
	previousUpdateCustomDomain, previousUpdateYes := updateCustomDomain, updateYes

	outputFormat, noWait = "json", true
	createRepo, createTag, createMarkLatestRelease = "acme/app", "v1.2.3", ""
	createDebug, createDisableCC = false, false
	createVariables, createSecrets, createSSHKeys = nil, nil, nil
	createCustomDomain, createHost, createReplaceID = "", "", ""
	createDisplayOrder, createVolumes = 0, nil
	deployTag, deployDebug, deployMarkLatestRelease = "", "", ""
	deployVariables, deploySecrets, deploySSHKeys = nil, nil, nil
	deployCustomDomain, deployHost, deployVolumes = "", "", nil
	updateTag, updateDebug, updateHold, updateMarkLatestRelease = "", "", "", ""
	updateVariables, updateSecrets, updateSSHKeys = nil, nil, nil
	updateCustomDomain, updateYes = "", false

	t.Cleanup(func() {
		outputFormat, noWait = previousOutput, previousNoWait
		createRepo, createTag = previousCreateRepo, previousCreateTag
		createMarkLatestRelease = previousCreateMarkLatestRelease
		createDebug, createDisableCC = previousCreateDebug, previousCreateDisableCC
		createVariables, createSecrets, createSSHKeys = previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys
		createCustomDomain, createHost, createReplaceID = previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID
		createDisplayOrder, createVolumes = previousCreateDisplayOrder, previousCreateVolumes
		deployTag, deployDebug, deployMarkLatestRelease = previousDeployTag, previousDeployDebug, previousDeployMarkLatestRelease
		deployVariables, deploySecrets, deploySSHKeys = previousDeployVariables, previousDeploySecrets, previousDeploySSHKeys
		deployCustomDomain, deployHost, deployVolumes = previousDeployCustomDomain, previousDeployHost, previousDeployVolumes
		updateTag, updateDebug = previousUpdateTag, previousUpdateDebug
		updateHold, updateMarkLatestRelease = previousUpdateHold, previousUpdateMarkLatestRelease
		updateVariables, updateSecrets, updateSSHKeys = previousUpdateVariables, previousUpdateSecrets, previousUpdateSSHKeys
		updateCustomDomain, updateYes = previousUpdateCustomDomain, previousUpdateYes
	})
}
