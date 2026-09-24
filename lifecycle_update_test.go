package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCandidateHoldOverridesCurrentVersion(t *testing.T) {
	previous := outputFormat
	outputFormat = "table"
	t.Cleanup(func() { outputFormat = previous })
	for _, tt := range []struct {
		name, config string
		held, want   bool
	}{
		{"explicit hold", `{"hold":true}`, false, true},
		{"explicit false", `{"hold":false}`, true, false},
		{"absent override", `{}`, true, true},
		{"null config", `null`, true, true},
		{"absent hold", `{}`, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var c containerView
			if err := json.Unmarshal([]byte(`{"status":"running","update_tag":"v2","update_status":"ready","update_config":`+tt.config+`}`), &c); err != nil {
				t.Fatal(err)
			}
			c.Held = tt.held
			if c.candidateHeld() != tt.want || isTerminal(c) != tt.want {
				t.Fatalf("candidate hold/terminal = %v/%v, want %v", c.candidateHeld(), isTerminal(c), tt.want)
			}
			out, err := captureTestStdout(func() error { return renderContainer(c) })
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{string(out), progressLine(c)} {
				if strings.Contains(text, "held for review") != tt.want || strings.Contains(text, "switching traffic") == tt.want {
					t.Fatalf("incorrect candidate label: %s", text)
				}
			}
			if strings.Contains(string(out), "Held:") != tt.want {
				t.Fatalf("incorrect held detail: %s", out)
			}
		})
	}
}

func TestHoldFlagsSendOmittedTrueAndFalse(t *testing.T) {
	for _, command := range []*cobra.Command{containerUpdateCmd, projectUpdateCmd, projectSettingsCmd} {
		for _, value := range []string{"omitted", "bare", "true", "false"} {
			t.Run(command.CommandPath()+"/"+value, func(t *testing.T) {
				var body map[string]any
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
						io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
						io.WriteString(w, `[]`)
					case r.Method == http.MethodGet:
						io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
					case strings.HasSuffix(r.URL.Path, "/update/plan"):
						projectID := ""
						if command == projectUpdateCmd {
							projectID = "project-1"
						}
						writeTestUpdatePlan(t, w, r, testContainerID, projectID, updateStrategyBlueGreen)
					default:
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
						}
						io.WriteString(w, `{}`)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				configureProjectCommandTest(t, server.URL)
				projectUpdateTag = "v2"
				flagName, wireName := "hold", "hold"
				identifier := testContainerID
				if command != containerUpdateCmd {
					identifier = "acme/app"
				}
				if command == projectSettingsCmd {
					flagName, wireName = "hold-by-default", "hold_by_default"
				}
				flag := command.Flags().Lookup(flagName)
				previousChanged := flag.Changed
				flag.Changed = false
				t.Cleanup(func() { flag.Changed = previousChanged })
				args := []string{identifier}
				if value == "bare" {
					args = append([]string{"--" + flagName}, args...)
				} else if value != "omitted" {
					args = append(args, "--"+flagName+"="+value)
				}
				if err := command.ParseFlags(args); err != nil {
					t.Fatal(err)
				}
				if err := command.Args(command, command.Flags().Args()); err != nil {
					t.Fatalf("flag consumed container argument: %v", err)
				}
				_, err := captureTestStdout(func() error { return command.RunE(command, command.Flags().Args()) })
				if command == projectSettingsCmd && value == "omitted" {
					if err == nil || body != nil {
						t.Fatalf("omitted settings: body=%v err=%v", body, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				got, exists := body[wireName]
				if exists != (value != "omitted") || (exists && got != (value != "false")) {
					t.Fatalf("body = %v for %s", body, value)
				}
			})
		}
	}
}

func TestUpdateTargetDowntimeConfirmation(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, tt := range []struct {
			name                string
			yes, currentReplace bool
			status              int
			response            string
			repeat              bool
			wantPosts           int
			wantErr             string
		}{
			{name: "target 8GPU requires explicit confirmation", status: 409, wantPosts: 1, wantErr: "requires interactive confirmation"},
			{name: "target 8GPU with yes", yes: true, status: 409, wantPosts: 2},
			{name: "mixed current replace and target 8GPU", yes: true, currentReplace: true, status: 409, wantPosts: 2},
			{name: "yes cannot loop", yes: true, status: 409, repeat: true, wantPosts: 2, wantErr: "409"},
			{name: "unrelated conflict", yes: true, status: 409, response: `{"code":"INVALID_CONTAINER_STATE","error":"already updating"}`, wantPosts: 1, wantErr: "already updating"},
			{name: "unstructured conflict", yes: true, status: 409, response: `{"error":"confirm downtime"}`, wantPosts: 1, wantErr: "confirm downtime"},
			{name: "forbidden", yes: true, status: 403, wantPosts: 1, wantErr: "403"},
			{name: "hold unavailable", yes: true, status: 400, response: `{"code":"HOLD_UNAVAILABLE","error":"cannot hold"}`, wantPosts: 1, wantErr: "cannot hold"},
		} {
			name := "container/"
			if project {
				name = "project/"
			}
			t.Run(name+tt.name, func(t *testing.T) {
				posts := 0
				var bodies []map[string]any
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
						io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
						if tt.currentReplace {
							io.WriteString(w, `[{"id":"current","name":"current-replace","repo":"acme/app","status":"running","gpus":8,"update_strategy":"replace"}]`)
						} else {
							io.WriteString(w, `[]`)
						}
					case r.Method == http.MethodGet:
						io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"running","gpus":1,"update_strategy":"blue_green"}`)
					case strings.HasSuffix(r.URL.Path, "/update/plan"):
						projectID := ""
						if project {
							projectID = "project-1"
						}
						writeTestUpdatePlan(t, w, r, testContainerID, projectID, updateStrategyBlueGreen)
					case r.Method == http.MethodPost:
						posts++
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
						}
						bodies = append(bodies, body)
						if posts == 1 || tt.repeat {
							w.WriteHeader(tt.status)
							response := tt.response
							if response == "" {
								response = `{"code":"DOWNTIME_CONFIRMATION_REQUIRED","error":"target requires replacement","update_strategy":"replace"}`
								if project {
									response = `{"code":"DOWNTIME_CONFIRMATION_REQUIRED","error":"target requires replacement","instances":["current-replace","target-8gpu"]}`
								}
							}
							io.WriteString(w, response)
						} else {
							io.WriteString(w, `{}`)
						}
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				configureProjectCommandTest(t, server.URL)
				updateYes, projectUpdateYes = tt.yes, tt.yes
				updateTag, projectUpdateTag = "v2-8gpu", "v2-8gpu"
				containerUpdateCmd.Flags().Lookup("tag").Changed = true
				out, err := captureTestStderr(func() error {
					_, err := captureTestStdout(func() error {
						if project {
							return projectUpdateCmd.RunE(projectUpdateCmd, []string{"acme/app"})
						}
						return containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID})
					})
					return err
				})
				if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				if posts != tt.wantPosts {
					t.Fatalf("posts = %d, want %d", posts, tt.wantPosts)
				}
				if _, ok := bodies[0]["confirm_downtime"]; ok {
					t.Fatal("target preflight must be unconfirmed")
				}
				if posts == 2 && bodies[1]["confirm_downtime"] != true {
					t.Fatal("retry must confirm downtime")
				}
				for _, body := range bodies {
					if body["tag"] != "v2-8gpu" {
						t.Fatalf("lost target tag: %v", body)
					}
				}
				if tt.status == 409 && tt.response == "" {
					wants := []string{"app", "downtime", "unreachable"}
					if project {
						wants = []string{"current-replace", "target-8gpu", "downtime", "unreachable"}
					}
					for _, want := range wants {
						if !strings.Contains(string(out), want) {
							t.Fatalf("warning lacks %q: %s", want, out)
						}
					}
				}
			})
		}
	}
}

func captureTestStderr(run func() error) ([]byte, error) {
	previous := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	defer writer.Close()
	os.Stderr = writer
	defer func() { os.Stderr = previous }()
	runErr := run()
	if err := writer.Close(); err != nil {
		return nil, err
	}
	output, err := io.ReadAll(reader)
	if runErr != nil {
		return output, runErr
	}
	return output, err
}

func TestChangedTagCanAllowHeldBlueGreenUpdate(t *testing.T) {
	for _, project := range []bool{false, true} {
		name := "container"
		if project {
			name = "project"
		}
		t.Run(name, func(t *testing.T) {
			posts := 0
			current := `{"id":"` + testContainerID + `","name":"app","repo":"acme/app","status":"running","current_tag":"v1","gpus":1,"update_strategy":"replace","volume_slots":[{"name":"optional"}]}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
					io.WriteString(w, `[`+current+`]`)
				case r.Method == http.MethodGet:
					io.WriteString(w, current)
				case strings.HasSuffix(r.URL.Path, "/update/plan"):
					projectID := ""
					if project {
						projectID = "project-1"
					}
					writeTestUpdatePlan(t, w, r, testContainerID, projectID, updateStrategyBlueGreen)
				case r.Method == http.MethodPost:
					posts++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["hold"] != true || body["tag"] != "v2-no-mounts" || body["confirm_downtime"] == true {
						t.Errorf("body = %v", body)
					}
					io.WriteString(w, `{}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			configureProjectCommandTest(t, server.URL)
			updateTag, projectUpdateTag = "v2-no-mounts", "v2-no-mounts"
			updateHold, projectUpdateHold = "true", "true"
			containerUpdateCmd.Flags().Lookup("tag").Changed = true
			containerUpdateCmd.Flags().Lookup("hold").Changed = true
			projectUpdateCmd.Flags().Lookup("hold").Changed = true
			_, err := captureTestStdout(func() error {
				if project {
					return projectUpdateCmd.RunE(projectUpdateCmd, []string{"acme/app"})
				}
				return containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID})
			})
			if err != nil || posts != 1 {
				t.Fatalf("must defer target strategy to server: posts=%d err=%v", posts, err)
			}
		})
	}
}

func TestKnownReplaceConfirmationDoesNotRetryAgain(t *testing.T) {
	for _, yes := range []bool{false, true} {
		name := "without confirmation"
		if yes {
			name = "already confirmed"
		}
		t.Run(name, func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","gpus":8,"update_strategy":"replace"}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/update/plan") {
					writeTestUpdatePlan(t, w, r, testContainerID, "", updateStrategyReplace)
					return
				}
				posts++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["confirm_downtime"] != true {
					t.Error("known replacement must be confirmed")
				}
				w.WriteHeader(http.StatusConflict)
				io.WriteString(w, `{"code":"DOWNTIME_CONFIRMATION_REQUIRED","error":"still needs confirmation"}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			updateYes = yes
			_, err := captureTestStdout(func() error { return containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID}) })
			wantPosts := 0
			wantErr := "requires interactive confirmation"
			if yes {
				wantPosts, wantErr = 1, "still needs confirmation"
			}
			if posts != wantPosts || err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("posts=%d err=%v", posts, err)
			}
		})
	}
}
