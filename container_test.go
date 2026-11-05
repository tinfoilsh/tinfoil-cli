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
	commandState := newCommandFixture()

	previousOutput := commandState.outputOpts.outputFormat
	t.Cleanup(func() { commandState.outputOpts.outputFormat = previousOutput })

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

			commandState.outputOpts.outputFormat = "table"
			output, err := captureTestStdout(func() error { return renderContainer(testStreams(), commandState.outputOpts, container) })
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

			commandState.outputOpts.outputFormat = "json"
			output, err = captureTestStdout(func() error { return renderContainer(testStreams(), commandState.outputOpts, container) })
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
	commandState := newCommandFixture()

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
			command:      commandState.containerCreateCmd,
			path:         "/api/containers",
			wantRequests: 2,
			wantBody: func(promote string) string {
				return `{` + promote + `"name":"app","repo":"acme/app","tag":"v1.2.3"}`
			},
			setValue: func(value string) { commandState.containerCreateOpts.createMarkLatestRelease = value },
			run: func() error {
				return commandState.containerCreateCmd.RunE(commandState.containerCreateCmd, []string{"app"})
			},
		},
		{
			name:         "deploy",
			command:      commandState.containerDeployCmd,
			path:         "/api/containers/" + containerID + "/deploy",
			wantRequests: 2,
			wantBody: func(promote string) string {
				return `{` + strings.TrimSuffix(promote, ",") + `}`
			},
			setValue: func(value string) { commandState.containerDeployOpts.deployMarkLatestRelease = value },
			run: func() error {
				return commandState.containerDeployCmd.RunE(commandState.containerDeployCmd, []string{containerID})
			},
		},
		{
			name:         "update",
			command:      commandState.containerUpdateCmd,
			path:         "/api/containers/" + containerID + "/update",
			wantRequests: 4,
			wantBody: func(promote string) string {
				return `{` + strings.TrimSuffix(promote, ",") + `}`
			},
			setValue: func(value string) { commandState.containerUpdateOpts.updateMarkLatestRelease = value },
			run: func() error {
				return commandState.containerUpdateCmd.RunE(commandState.containerUpdateCmd, []string{containerID})
			},
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
					case r.Method == http.MethodPost && r.URL.Path == "/api/containers/"+containerID+"/update/plan":
						writeTestUpdatePlan(t, w, r, containerID, "", updateStrategyBlueGreen)
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

				configureContainerPromotionTest(commandState, t, server.URL)
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
	commandState := newCommandFixture()

	for _, command := range []*cobra.Command{
		commandState.containerCreateCmd,
		commandState.containerDeployCmd,
		commandState.containerUpdateCmd,
		commandState.projectUpdateCmd,
	} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			if got := command.Flags().Lookup("mark-latest").NoOptDefVal; got != "" {
				t.Fatalf("NoOptDefVal = %q, want empty", got)
			}
		})
	}
}

func configureContainerPromotionTest(commandState *commandFixture, t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	for command, names := range map[*cobra.Command][]string{
		commandState.containerCreateCmd: {"display-order", "mark-latest", "volume"},
		commandState.containerDeployCmd: {"tag", "variable", "secret", "ssh-key", "debug", "mark-latest", "custom-domain", "host", "volume", "no-wait"},
		commandState.containerUpdateCmd: {"tag", "variable", "secret", "ssh-key", "debug", "hold", "mark-latest", "custom-domain", "yes", "no-wait"},
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

	previousOutput, previousNoWait := commandState.outputOpts.outputFormat, commandState.waitOpts.noWait
	previousCreateRepo, previousCreateTag := commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag
	previousCreateSource, previousCreateRevision := commandState.containerCreateOpts.createSource, commandState.containerCreateOpts.createRevision
	previousLocalConfigFile, previousLocalConfigBytes := commandState.rootOpts.localConfigFile, commandState.rootOpts.localConfigBytes
	previousCreateMarkLatestRelease := commandState.containerCreateOpts.createMarkLatestRelease
	previousCreateDebug, previousCreateDisableCC := commandState.containerCreateOpts.createDebug, commandState.containerCreateOpts.createDisableCC
	previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys := commandState.containerCreateOpts.createVariables, commandState.containerCreateOpts.createSecrets, commandState.containerCreateOpts.createSSHKeys
	previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID := commandState.containerCreateOpts.createCustomDomain, commandState.containerCreateOpts.createHost, commandState.containerCreateOpts.createReplaceID
	previousCreateDisplayOrder, previousCreateVolumes := commandState.containerCreateOpts.createDisplayOrder, commandState.containerCreateOpts.createVolumes
	previousDeployTag, previousDeployDebug := commandState.containerDeployOpts.deployTag, commandState.containerDeployOpts.deployDebug
	previousDeployMarkLatestRelease := commandState.containerDeployOpts.deployMarkLatestRelease
	previousDeployVariables, previousDeploySecrets, previousDeploySSHKeys := commandState.containerDeployOpts.deployVariables, commandState.containerDeployOpts.deploySecrets, commandState.containerDeployOpts.deploySSHKeys
	previousDeployCustomDomain, previousDeployHost, previousDeployVolumes := commandState.containerDeployOpts.deployCustomDomain, commandState.containerDeployOpts.deployHost, commandState.containerDeployOpts.deployVolumes
	previousUpdateTag, previousUpdateDebug := commandState.containerUpdateOpts.updateTag, commandState.containerUpdateOpts.updateDebug
	previousUpdateHold, previousUpdateMarkLatestRelease := commandState.containerUpdateOpts.updateHold, commandState.containerUpdateOpts.updateMarkLatestRelease
	previousUpdateVariables, previousUpdateSecrets, previousUpdateSSHKeys := commandState.containerUpdateOpts.updateVariables, commandState.containerUpdateOpts.updateSecrets, commandState.containerUpdateOpts.updateSSHKeys
	previousUpdateCustomDomain, previousUpdateYes := commandState.containerUpdateOpts.updateCustomDomain, commandState.containerUpdateOpts.updateYes

	commandState.outputOpts.outputFormat, commandState.waitOpts.noWait = "json", true
	commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag, commandState.containerCreateOpts.createMarkLatestRelease = "acme/app", "v1.2.3", ""
	commandState.containerCreateOpts.createSource, commandState.containerCreateOpts.createRevision = containerSourceGitHub, ""
	commandState.rootOpts.localConfigFile, commandState.rootOpts.localConfigBytes = "", nil
	commandState.containerCreateOpts.createDebug, commandState.containerCreateOpts.createDisableCC = false, false
	commandState.containerCreateOpts.createVariables, commandState.containerCreateOpts.createSecrets, commandState.containerCreateOpts.createSSHKeys = nil, nil, nil
	commandState.containerCreateOpts.createCustomDomain, commandState.containerCreateOpts.createHost, commandState.containerCreateOpts.createReplaceID = "", "", ""
	commandState.containerCreateOpts.createDisplayOrder, commandState.containerCreateOpts.createVolumes = 0, nil
	commandState.containerDeployOpts.deployTag, commandState.containerDeployOpts.deployDebug, commandState.containerDeployOpts.deployMarkLatestRelease = "", "", ""
	commandState.containerDeployOpts.deployVariables, commandState.containerDeployOpts.deploySecrets, commandState.containerDeployOpts.deploySSHKeys = nil, nil, nil
	commandState.containerDeployOpts.deployCustomDomain, commandState.containerDeployOpts.deployHost, commandState.containerDeployOpts.deployVolumes = "", "", nil
	commandState.containerUpdateOpts.updateTag, commandState.containerUpdateOpts.updateDebug, commandState.containerUpdateOpts.updateHold, commandState.containerUpdateOpts.updateMarkLatestRelease = "", "", "", ""
	commandState.containerUpdateOpts.updateVariables, commandState.containerUpdateOpts.updateSecrets, commandState.containerUpdateOpts.updateSSHKeys = nil, nil, nil
	commandState.containerUpdateOpts.updateCustomDomain, commandState.containerUpdateOpts.updateYes = "", false

	t.Cleanup(func() {
		commandState.outputOpts.outputFormat, commandState.waitOpts.noWait = previousOutput, previousNoWait
		commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = previousCreateRepo, previousCreateTag
		commandState.containerCreateOpts.createSource, commandState.containerCreateOpts.createRevision = previousCreateSource, previousCreateRevision
		commandState.rootOpts.localConfigFile, commandState.rootOpts.localConfigBytes = previousLocalConfigFile, previousLocalConfigBytes
		commandState.containerCreateOpts.createMarkLatestRelease = previousCreateMarkLatestRelease
		commandState.containerCreateOpts.createDebug, commandState.containerCreateOpts.createDisableCC = previousCreateDebug, previousCreateDisableCC
		commandState.containerCreateOpts.createVariables, commandState.containerCreateOpts.createSecrets, commandState.containerCreateOpts.createSSHKeys = previousCreateVariables, previousCreateSecrets, previousCreateSSHKeys
		commandState.containerCreateOpts.createCustomDomain, commandState.containerCreateOpts.createHost, commandState.containerCreateOpts.createReplaceID = previousCreateCustomDomain, previousCreateHost, previousCreateReplaceID
		commandState.containerCreateOpts.createDisplayOrder, commandState.containerCreateOpts.createVolumes = previousCreateDisplayOrder, previousCreateVolumes
		commandState.containerDeployOpts.deployTag, commandState.containerDeployOpts.deployDebug, commandState.containerDeployOpts.deployMarkLatestRelease = previousDeployTag, previousDeployDebug, previousDeployMarkLatestRelease
		commandState.containerDeployOpts.deployVariables, commandState.containerDeployOpts.deploySecrets, commandState.containerDeployOpts.deploySSHKeys = previousDeployVariables, previousDeploySecrets, previousDeploySSHKeys
		commandState.containerDeployOpts.deployCustomDomain, commandState.containerDeployOpts.deployHost, commandState.containerDeployOpts.deployVolumes = previousDeployCustomDomain, previousDeployHost, previousDeployVolumes
		commandState.containerUpdateOpts.updateTag, commandState.containerUpdateOpts.updateDebug = previousUpdateTag, previousUpdateDebug
		commandState.containerUpdateOpts.updateHold, commandState.containerUpdateOpts.updateMarkLatestRelease = previousUpdateHold, previousUpdateMarkLatestRelease
		commandState.containerUpdateOpts.updateVariables, commandState.containerUpdateOpts.updateSecrets, commandState.containerUpdateOpts.updateSSHKeys = previousUpdateVariables, previousUpdateSecrets, previousUpdateSSHKeys
		commandState.containerUpdateOpts.updateCustomDomain, commandState.containerUpdateOpts.updateYes = previousUpdateCustomDomain, previousUpdateYes
	})
}
