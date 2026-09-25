package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const updatePlanFixture = `{"read_only":true,"instance_id":"61bd4a3e-5b48-4320-9215-0c7a7f974979","name":"app","current":{"tag":"v1","cpus":2,"memory_mb":4096,"gpus":0},"target":{"tag":"v2","cpus":4,"memory_mb":8192,"gpus":0},"update_strategy":"blue_green","downtime_required":false,"hold":false,"hold_source":"project","hold_available":true,"mark_latest_release":true,"configuration_changes":{"variables":{"added":[],"changed":["MODE"],"removed":[]},"secrets":{"added":[],"changed":[],"removed":[]},"ssh_keys":{"added":[],"changed":[],"removed":[]},"settings":[],"secrets_refreshed":["TOKEN"]},"volume_data":"retained","cost_estimate":{"available":false,"reason":"a reliable account-specific update cost estimate is unavailable"}}`

func writeTestUpdatePlan(t *testing.T, w http.ResponseWriter, r *http.Request, id, projectID, strategy string) {
	t.Helper()
	var plan updatePlan
	if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
		t.Error(err)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Error(err)
		return
	}
	plan.InstanceID = id
	plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = strategy, strategy == updateStrategyReplace, strategy != updateStrategyReplace
	if tag, ok := body["tag"].(string); ok {
		plan.Target.Tag = tag
	}
	if hold, ok := body["hold"].(bool); ok {
		plan.Hold, plan.HoldSource = hold, "request"
	}
	if latest, ok := body["mark_latest_release"].(bool); ok {
		plan.MarkLatestRelease = latest
	}
	var response any = plan
	if projectID != "" {
		response = map[string]any{"read_only": true, "project_id": projectID, "latest_release_tag": "v1", "eligible_count": 1, "skipped_count": 0, "failed_count": 0, "results": []any{map[string]any{"instance_id": id, "name": "app", "status": "planned", "plan": plan, "error": nil}}}
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.Error(err)
	}
}

func TestHumanUpdatePlanShowsChangesWithoutValues(t *testing.T) {
	var plan updatePlan
	if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
		t.Fatal(err)
	}
	plan.Current.MemoryMB = nil
	var out bytes.Buffer
	renderUpdatePlan(&out, plan)
	for _, want := range []string{"read-only", "v1 -> v2", "CPU: 2 -> 4", "RAM (MB): not available -> 8192", "GPU: 0 -> 0", "source: project", "Volume data: retained", "current settings and current secret values", "not a historical snapshot", "changed [MODE]", "Refresh current secret values: TOKEN", "repository-wide latest release", "--mark-latest=false", "Estimated cost: not available"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
}

func TestUpdatePlanDoesNotEchoSubmittedVariableValues(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"id":"`+testContainerID+`","name":"app"}`)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		if strings.HasSuffix(r.URL.Path, "/plan") {
			io.WriteString(w, updatePlanFixture)
		} else {
			io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	var stdout []byte
	stderr, err := captureTestStderr(func() error {
		var err error
		stdout, err = captureTestStdout(func() error {
			return executeLifecycleCLI(t, "container", "update", testContainerID, "--variable", "MODE=private-value-never-print", "--no-wait", "--yes", "-o", "table")
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 {
		t.Fatalf("expected plan, recheck, then update, got %d requests", len(bodies))
	}
	for _, body := range bodies {
		if body["variables"].(map[string]any)["MODE"] != "private-value-never-print" {
			t.Fatal("request body lost variable value")
		}
	}
	if strings.Contains(string(stdout)+string(stderr), "private-value-never-print") {
		t.Fatal("variable value leaked to output")
	}
	if !strings.Contains(string(stderr), "changed [MODE]") || !strings.Contains(string(stderr), "repository-wide latest release") {
		t.Fatalf("yes/no-wait masked changes: %s", stderr)
	}
}

func TestProjectSettingsFullCobraBooleanSyntax(t *testing.T) {
	for _, flag := range []string{"--hold-by-default", "--hold-by-default=true", "--hold-by-default=false"} {
		t.Run(flag, func(t *testing.T) {
			var body map[string]bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					return
				}
				if r.Method != http.MethodPatch {
					t.Errorf("method %s", r.Method)
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				io.WriteString(w, `{"id":"project-1","repo":"acme/app"}`)
			}))
			defer server.Close()
			configureProjectCommandTest(t, server.URL)
			_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "project", "settings", "acme/app", flag) })
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := body["hold_by_default"]; !ok || value != (flag != "--hold-by-default=false") {
				t.Fatalf("body %v", body)
			}
		})
	}
}

func TestProjectPlanReportsSkippedAndFailedInstances(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(boolText(failed), func(t *testing.T) {
			updates := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet:
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
				case strings.HasSuffix(r.URL.Path, "/plan"):
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					var plan map[string]any
					if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
						t.Error(err)
					}
					status, failedCount, skippedCount := "skipped", 0, 1
					if failed {
						status, failedCount, skippedCount = "failed", 1, 0
					}
					results := []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan, "error": nil}}
					if body["instance_ids"] == nil {
						results = append(results, map[string]any{"instance_id": "other", "name": "other", "status": status, "plan": nil, "error": "instance cannot update"})
					} else {
						skippedCount, failedCount = 0, 0
					}
					json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "latest_release_tag": "release-stable", "eligible_count": 1, "skipped_count": skippedCount, "failed_count": failedCount, "results": results})
				case strings.HasSuffix(r.URL.Path, "/update"):
					updates++
					io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","name":"app","status":"updating"}]}`)
				default:
					t.Errorf("unexpected path %s", r.URL)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			configureProjectCommandTest(t, server.URL)
			projectUpdateTag = "v2"
			outputFormat = "table"
			out, err := captureTestStderr(func() error {
				_, err := captureTestStdout(func() error { return projectUpdateCmd.RunE(projectUpdateCmd, []string{"acme/app"}) })
				return err
			})
			wantUpdates := 1
			if failed {
				wantUpdates = 0
				if err == nil || !strings.Contains(err.Error(), "no update was sent") {
					t.Fatalf("err %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "1 skipped") {
				t.Fatalf("skipped instance must remain incomplete: %v", err)
			}
			if updates != wantUpdates {
				t.Fatalf("updates %d", updates)
			}
			for _, want := range []string{"GitHub latest release: release-stable", "instance cannot update", "1 eligible"} {
				if !strings.Contains(string(out), want) {
					t.Fatalf("missing %q: %s", want, out)
				}
			}
		})
	}
}

func TestHoldSpaceFalseIsRejectedBeforeRequest(t *testing.T) {
	for _, args := range [][]string{
		{"container", "update", testContainerID, "--hold", "false"},
		{"project", "update", "acme/app", "--tag", "v2", "--hold", "false"},
		{"project", "settings", "acme/app", "--hold-by-default", "false"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid args made request"); w.WriteHeader(500) }))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			configureProjectCommandTest(t, server.URL)
			if err := executeLifecycleCLI(t, args...); err == nil {
				t.Fatal("space-separated false accepted")
			}
		})
	}
}

func executeLifecycleCLI(t *testing.T, args ...string) error {
	t.Helper()
	var reset func(*cobra.Command)
	reset = func(cmd *cobra.Command) {
		for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
			set.VisitAll(func(flag *pflag.Flag) {
				value, changed := flag.Value.String(), flag.Changed
				if slice, ok := flag.Value.(pflag.SliceValue); ok {
					values := append([]string(nil), slice.GetSlice()...)
					t.Cleanup(func() { _ = slice.Replace(values); flag.Changed = changed })
				} else {
					t.Cleanup(func() { _ = flag.Value.Set(value); flag.Changed = changed })
				}
				flag.Changed = false
			})
		}
		for _, child := range cmd.Commands() {
			reset(child)
		}
	}
	reset(rootCmd)
	rootCmd.SetArgs(args)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	return rootCmd.Execute()
}

func TestUpdatePlanPrecedesMutationThroughCobra(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, holdFlag := range []string{"", "--hold", "--hold=true", "--hold=false"} {
			t.Run(boolText(project)+holdFlag, func(t *testing.T) {
				var plannedBody, updateBody map[string]any
				var paths []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					paths = append(paths, r.Method+" "+r.URL.Path)
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/projects":
						io.WriteString(w, `[{"id":"project-1","repo":"acme/app","hold_by_default":true}]`)
					case r.Method == http.MethodGet:
						io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","current_tag":"v1","update_strategy":"replace"}`)
					case strings.HasSuffix(r.URL.Path, "/update/plan"):
						if err := json.NewDecoder(r.Body).Decode(&plannedBody); err != nil {
							t.Error(err)
						}
						var plan map[string]any
						if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
							t.Error(err)
						}
						plan["hold"] = true
						if hold, ok := plannedBody["hold"]; ok {
							plan["hold"], plan["hold_source"] = hold, "request"
						}
						if project {
							json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "latest_release_tag": "v1", "eligible_count": 1, "skipped_count": 0, "failed_count": 0, "results": []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan, "error": nil}}})
						} else {
							json.NewEncoder(w).Encode(plan)
						}
					case strings.HasSuffix(r.URL.Path, "/update"):
						if plannedBody == nil {
							t.Error("update before plan")
						}
						if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
							t.Error(err)
						}
						if project {
							io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","name":"app","status":"updating"}]}`)
						} else {
							io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
						}
					default:
						t.Errorf("unexpected request %s", r.URL)
						w.WriteHeader(404)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				configureProjectCommandTest(t, server.URL)
				args := []string{"container", "update", testContainerID, "--tag", "v2", "--no-wait", "--yes", "-o", "json"}
				if project {
					args = []string{"project", "update", "acme/app", "--tag", "v2", "--yes", "-o", "json"}
				}
				if holdFlag != "" {
					args = append(args, holdFlag)
				}
				var stdout []byte
				stderr, err := captureTestStderr(func() error {
					var err error
					stdout, err = captureTestStdout(func() error { return executeLifecycleCLI(t, args...) })
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				if !json.Valid(stdout) || !json.Valid(stderr) {
					t.Fatalf("JSON outputs: stdout=%s stderr=%s", stdout, stderr)
				}
				if !strings.Contains(string(stderr), `"read_only":true`) || !strings.Contains(string(stderr), `"changed":["MODE"]`) {
					t.Fatalf("missing plan %s", stderr)
				}
				for _, body := range []map[string]any{plannedBody, updateBody} {
					value, present := body["hold"]
					if present != (holdFlag != "") || present && value != (holdFlag != "--hold=false") {
						t.Fatalf("hold changed: %v", body)
					}
					if _, ok := body["confirm_downtime"]; ok {
						t.Fatalf("used stale container strategy: %v", body)
					}
				}
				if len(paths) != 4 {
					t.Fatalf("requests %v", paths)
				}
			})
		}
	}
}

func TestUpdatePlanFailurePreventsMutation(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"id":"`+testContainerID+`"}`)
					return
				}
				posts++
				if !strings.HasSuffix(r.URL.Path, "/plan") {
					t.Error("mutation after plan failure")
				}
				w.WriteHeader(status)
				io.WriteString(w, `{}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			if err := containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID}); err == nil {
				t.Fatal("accepted failed plan")
			}
			if posts != 1 {
				t.Fatalf("posts %d", posts)
			}
		})
	}
}
