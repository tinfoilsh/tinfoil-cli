package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const consentProcessEnv = "TINFOIL_TEST_CONSENT_PROCESS"

func TestUpdateConsentCLIProcess(t *testing.T) {
	if os.Getenv(consentProcessEnv) != "1" {
		return
	}
	rootCmd.SetArgs(os.Args[3:])
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func consentCLIProcess(t *testing.T, serverURL string, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestUpdateConsentCLIProcess$", "--"}, args...)...)
	if binary := os.Getenv("TINFOIL_TEST_CLI_BINARY"); binary != "" {
		cmd = exec.CommandContext(ctx, binary, args...)
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), consentProcessEnv + "=1", envCPURL + "=" + serverURL,
		envAdminKey + "=admin_local_test", envAPIKey + "=", envConfigPath + "=" + filepath.Join(t.TempDir(), "config.json"), "TINFOIL_NO_UPDATE_CHECK=1", "GORACE=atexit_sleep_ms=0"}
	return cmd
}

type consentPromptWriter struct {
	buffer   bytes.Buffer
	stdin    io.Writer
	onPrompt func(int) string
	prompts  int
}

func (w *consentPromptWriter) Write(data []byte) (int, error) {
	n, err := w.buffer.Write(data)
	for w.prompts < strings.Count(w.buffer.String(), `Type "yes" to proceed: `) {
		w.prompts++
		if _, writeErr := io.WriteString(w.stdin, w.onPrompt(w.prompts)); writeErr != nil {
			return n, writeErr
		}
	}
	return n, err
}

func runConsentTTY(t *testing.T, cmd *exec.Cmd, onPrompt func(int) string) (string, int, error) {
	t.Helper()
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("PTY tests require script")
	}
	args := cmd.Args
	switch runtime.GOOS {
	case "darwin":
		cmd.Args = append([]string{script, "-q", os.DevNull}, args...)
	case "linux":
		quoted := make([]string, len(args))
		for i, arg := range args {
			quoted[i] = shellQuote(arg)
		}
		cmd.Args = []string{script, "-q", "-e", "-c", strings.Join(quoted, " "), os.DevNull}
	default:
		t.Skip("PTY test uses the Darwin/Linux script utility")
	}
	cmd.Path = script
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	w := &consentPromptWriter{stdin: stdin, onPrompt: onPrompt}
	cmd.Stdout, cmd.Stderr = w, w
	err = cmd.Run()
	return w.buffer.String(), w.prompts, err
}

func TestChangedReviewedTargetRequiresFreshManualConsent(t *testing.T) {
	for _, answer := range []string{"no\n", "yes\n", "interrupt"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			var mu sync.Mutex
			plans, updates := 0, 0
			targetChanged := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"id":"`+testContainerID+`","name":"app"}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/plan") {
					plans++
					var plan updatePlan
					json.Unmarshal([]byte(updatePlanFixture), &plan)
					plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = updateStrategyReplace, true, false
					if targetChanged {
						plan.Target.CPUs = 8
						plan.ConfigurationChanges.Secrets.Changed = []string{"TOKEN"}
					}
					json.NewEncoder(w).Encode(plan)
					return
				}
				updates++
				io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
			}))
			defer server.Close()
			cmd := consentCLIProcess(t, server.URL, "container", "update", testContainerID, "--tag", "v2", "--no-wait")
			out, prompts, err := runConsentTTY(t, cmd, func(prompt int) string {
				mu.Lock()
				defer mu.Unlock()
				if updates != 0 {
					t.Error("mutation while awaiting human consent")
				}
				if answer == "interrupt" {
					return "\x03"
				}
				if prompt == 1 {
					targetChanged = true
					return "yes\n"
				}
				return answer
			})
			mu.Lock()
			defer mu.Unlock()
			if answer == "interrupt" {
				if prompts != 1 || updates != 0 || plans != 1 {
					t.Fatalf("interrupted prompt mutated target: prompts=%d plans=%d updates=%d\n%s", prompts, plans, updates, out)
				}
				return
			}
			if prompts != 2 || !strings.Contains(out, "CPU: 2 -> 8") || !strings.Contains(out, "changed [TOKEN]") {
				t.Fatalf("changed target not reviewed again: prompts=%d plans=%d updates=%d err=%v\n%s", prompts, plans, updates, err, out)
			}
			if answer == "yes\n" {
				if err != nil || updates != 1 || plans != 3 {
					t.Fatalf("fresh consent/recheck failed: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
				}
			} else if updates != 0 || !strings.Contains(out, "aborted") {
				t.Fatalf("rejected changed plan executed: updates=%d\n%s", updates, out)
			}
		})
	}
}

func TestAutomationReplansChangedTargetsAndStopsChurn(t *testing.T) {
	for _, churn := range []bool{false, true} {
		t.Run(boolText(churn), func(t *testing.T) {
			var mu sync.Mutex
			plans, updates := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"id":"`+testContainerID+`"}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/plan") {
					plans++
					var plan updatePlan
					json.Unmarshal([]byte(updatePlanFixture), &plan)
					if plans > 1 {
						plan.Target.CPUs = 8
						plan.Hold = true
						plan.ConfigurationChanges.Settings = []string{"debug"}
					}
					if churn {
						plan.Target.CPUs += plans
					}
					json.NewEncoder(w).Encode(plan)
					return
				}
				updates++
				io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
			}))
			defer server.Close()
			cmd := consentCLIProcess(t, server.URL, "container", "update", testContainerID, "--tag", "v2", "--yes", "--no-wait")
			out, err := cmd.CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if churn {
				if err == nil || updates != 0 || plans != maxUpdatePlanReviews+1 || !strings.Contains(string(out), "did not stabilize") {
					t.Fatalf("unbounded/unsafe churn: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
				}
			} else if err != nil || updates != 1 || plans != 3 || !strings.Contains(string(out), "CPU: 2 -> 8") || !strings.Contains(string(out), "Changed settings: debug") || !strings.Contains(string(out), "Accepting the displayed update plan automatically (--yes)") {
				t.Fatalf("automation failed to review/recheck changed plan: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
			}
		})
	}
}

func TestProjectExecutionFreezesReviewedEligibleIDs(t *testing.T) {
	var mu sync.Mutex
	var execution map[string]any
	var affected []string
	var recheckIDs [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/plan") {
			var plan updatePlan
			if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
				t.Error(err)
				return
			}
			plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = updateStrategyReplace, true, false
			results := []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan, "error": nil}}
			skipped := 0
			if selected, ok := body["instance_ids"].([]any); ok {
				var ids []string
				for _, id := range selected {
					ids = append(ids, id.(string))
				}
				recheckIDs = append(recheckIDs, ids)
			} else {
				skipped = 1
				results = append(results, map[string]any{"instance_id": "B", "name": "booting", "status": "skipped", "plan": nil, "error": "instance is deploying"})
			}
			json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "latest_release_tag": "v1", "eligible_count": 1, "skipped_count": skipped, "failed_count": 0, "results": results})
			return
		}
		execution = body
		affected = []string{testContainerID, "B", "C"}
		if selected, ok := body["instance_ids"].([]any); ok {
			affected = nil
			for _, id := range selected {
				affected = append(affected, id.(string))
			}
		}
		var results []projectInstanceResult
		for _, id := range affected {
			results = append(results, projectInstanceResult{ContainerID: id, Name: id, Status: "updating"})
		}
		json.NewEncoder(w).Encode(projectUpdateResponse{Results: results})
	}))
	defer server.Close()
	cmd := consentCLIProcess(t, server.URL, "project", "update", "acme/app", "--tag", "v2", "--yes", "-o", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("actual execution body: %v", execution)
	if !reflect.DeepEqual(execution["instance_ids"], []any{testContainerID}) {
		t.Fatalf("execution broadened beyond reviewed A: %v (CLI error %v, stderr %s)", execution, err, stderr.String())
	}
	if !reflect.DeepEqual(affected, []string{testContainerID}) {
		t.Fatalf("newly running B or newly created C was touched: %v", affected)
	}
	if len(recheckIDs) == 0 || !reflect.DeepEqual(recheckIDs[0], []string{testContainerID}) {
		t.Fatalf("missing exact-ID recheck: %v", recheckIDs)
	}
	if err == nil {
		t.Fatal("skipped B incorrectly reported success")
	}
	var response projectUpdateResponse
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("invalid final JSON %s: %v", out, err)
	}
	if len(response.Results) != 2 || response.Results[1].ContainerID != "B" || response.Results[1].Status != projectInstanceStatusSkipped {
		t.Fatalf("lost initial skipped result: %s", out)
	}
}

func TestUpdateReviewComparisonCoversReviewedFields(t *testing.T) {
	base := func() updateReview {
		var plan updatePlan
		if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
			t.Fatal(err)
		}
		return updateReview{plans: []updatePlan{plan}}
	}
	for _, tc := range []struct {
		name   string
		change func(*updatePlan)
	}{
		{"identity", func(p *updatePlan) { p.InstanceID = "other" }},
		{"tag", func(p *updatePlan) { p.Target.Tag = "different" }},
		{"CPU", func(p *updatePlan) { p.Target.CPUs++ }},
		{"RAM", func(p *updatePlan) { *p.Target.MemoryMB++ }},
		{"GPU", func(p *updatePlan) { p.Target.GPUs++ }},
		{"current tag", func(p *updatePlan) { p.Current.Tag = "different" }},
		{"strategy", func(p *updatePlan) {
			p.UpdateStrategy = updateStrategyReplace
			p.DowntimeRequired = true
			p.HoldAvailable = false
		}},
		{"hold", func(p *updatePlan) { p.Hold = !p.Hold }},
		{"hold source", func(p *updatePlan) { p.HoldSource = "request" }},
		{"mark latest", func(p *updatePlan) { p.MarkLatestRelease = !p.MarkLatestRelease }},
		{"variables", func(p *updatePlan) { p.ConfigurationChanges.Variables.Changed = []string{"OTHER"} }},
		{"secrets", func(p *updatePlan) { p.ConfigurationChanges.Secrets.Removed = []string{"TOKEN"} }},
		{"secret refresh", func(p *updatePlan) { p.ConfigurationChanges.SecretsRefreshed = []string{"NEW"} }},
		{"SSH keys", func(p *updatePlan) { p.ConfigurationChanges.SSHKeys.Added = []string{"operator"} }},
		{"settings", func(p *updatePlan) { p.ConfigurationChanges.Settings = []string{"debug"} }},
		{"volume retention", func(p *updatePlan) { p.VolumeData = "changed" }},
		{"cost", func(p *updatePlan) { p.CostEstimate.Reason = "different" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := base(), base()
			tc.change(&right.plans[0])
			if sameUpdateReview(left, right) {
				t.Fatal("meaningful change ignored")
			}
		})
	}
	left, right := base(), base()
	left.plans[0].ConfigurationChanges.Variables.Changed = []string{"A", "B"}
	right.plans[0].ConfigurationChanges.Variables.Changed = []string{"B", "A"}
	right.plans[0].ConfigurationChanges.Settings = nil
	if !sameUpdateReview(left, right) {
		t.Fatal("order or nil/empty differences triggered consent")
	}
	if !reflect.DeepEqual(right.plans[0].ConfigurationChanges.Variables.Changed, []string{"B", "A"}) {
		t.Fatal("comparison mutated the displayed plan")
	}
	left.project = &projectUpdatePlan{LatestReleaseTag: "v1"}
	right.project = &projectUpdatePlan{LatestReleaseTag: "v2"}
	if sameUpdateReview(left, right) {
		t.Fatal("repository-wide latest change ignored")
	}
}

func TestProjectRecheckFailsClosedOnInvalidSelection(t *testing.T) {
	for _, variant := range []string{"extra", "missing", "duplicate", "all skipped", "failed", "forbidden"} {
		t.Run(variant, func(t *testing.T) {
			var mu sync.Mutex
			plans, updates := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/plan") {
					updates++
					io.WriteString(w, `{"results":[]}`)
					return
				}
				plans++
				var plan updatePlan
				json.Unmarshal([]byte(updatePlanFixture), &plan)
				entry := map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan, "error": nil}
				results := []any{entry}
				eligible, skipped, failed := 1, 0, 0
				if plans > 1 {
					switch variant {
					case "extra":
						results = append(results, map[string]any{"instance_id": "C", "name": "new", "status": "skipped", "plan": nil, "error": "new instance"})
						skipped++
					case "missing":
						results = nil
						eligible = 0
					case "duplicate":
						results = append(results, entry)
						eligible++
					case "all skipped":
						entry["status"], entry["plan"], entry["error"] = "skipped", nil, "already updating"
						eligible, skipped = 0, 1
					case "failed":
						entry["status"], entry["plan"], entry["error"] = "failed", nil, "invalid configuration"
						eligible, failed = 0, 1
					case "forbidden":
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "latest_release_tag": "v1", "eligible_count": eligible, "skipped_count": skipped, "failed_count": failed, "results": results})
			}))
			defer server.Close()
			cmd := consentCLIProcess(t, server.URL, "project", "update", "acme/app", "--tag", "v2", "--yes", "-o", "json")
			out, err := cmd.CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if err == nil || updates != 0 || plans != 2 {
				t.Fatalf("unsafe recheck %s: plans=%d updates=%d err=%v\n%s", variant, plans, updates, err, out)
			}
		})
	}
}

func TestProjectManualConsentFreezesSelection(t *testing.T) {
	for _, variant := range []string{"B becomes ready and C is created", "B loses eligibility", "cancel"} {
		t.Run(variant, func(t *testing.T) {
			var mu sync.Mutex
			changed := false
			plans, updates := 0, 0
			var selectedAtRecheck [][]string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					return
				}
				var body struct {
					IDs     []string `json:"instance_ids"`
					Confirm bool     `json:"confirm_downtime"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/plan") {
					updates++
					if !reflect.DeepEqual(body.IDs, []string{testContainerID}) || !body.Confirm {
						t.Errorf("execution exceeded reviewed selection: %+v", body)
					}
					io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","name":"app","status":"updating"}]}`)
					return
				}
				plans++
				if plans > 1 {
					selectedAtRecheck = append(selectedAtRecheck, body.IDs)
				}
				ids := body.IDs
				if len(ids) == 0 {
					ids = []string{testContainerID, "B"}
					if changed {
						ids = append(ids, "C")
					}
				}
				var results []any
				eligible, skipped := 0, 0
				for _, id := range ids {
					if id == "B" && changed == (variant == "B loses eligibility") {
						skipped++
						results = append(results, map[string]any{"instance_id": id, "name": id, "status": "skipped", "plan": nil, "error": "instance is deploying"})
						continue
					}
					var plan updatePlan
					if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
						t.Error(err)
						return
					}
					plan.InstanceID, plan.Name = id, id
					plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = updateStrategyReplace, true, false
					eligible++
					results = append(results, map[string]any{"instance_id": id, "name": id, "status": "planned", "plan": plan, "error": nil})
				}
				json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "eligible_count": eligible, "skipped_count": skipped, "failed_count": 0, "results": results})
			}))
			defer server.Close()
			cmd := consentCLIProcess(t, server.URL, "project", "update", "acme/app", "--tag", "v2")
			out, prompts, err := runConsentTTY(t, cmd, func(prompt int) string {
				mu.Lock()
				defer mu.Unlock()
				if updates != 0 {
					t.Error("project mutated before consent")
				}
				changed = true
				if variant == "cancel" {
					return "no\n"
				}
				return "yes\n"
			})
			mu.Lock()
			defer mu.Unlock()
			if variant == "cancel" {
				if updates != 0 || plans != 1 || prompts != 1 || !strings.Contains(out, "aborted") {
					t.Fatalf("canceled project update: plans=%d updates=%d prompts=%d\n%s", plans, updates, prompts, out)
				}
				return
			}
			wantIDs := [][]string{{testContainerID}}
			if variant == "B loses eligibility" {
				wantIDs = [][]string{{testContainerID, "B"}, {testContainerID}}
			}
			if updates != 1 || prompts != len(wantIDs) || !reflect.DeepEqual(selectedAtRecheck, wantIDs) || !strings.Contains(out, "1 skipped") || !strings.Contains(out, "not executed: excluded by update plan") {
				t.Fatalf("incorrect consent/exclusion: plans=%d updates=%d prompts=%d rechecks=%v err=%v\n%s", plans, updates, prompts, selectedAtRecheck, err, out)
			}
		})
	}
}

func TestInitialProjectPlanRejectsInvalidOrEmptySelection(t *testing.T) {
	for _, variant := range []string{"foreign ID rejected", "foreign ID omitted", "unselected ID returned", "all skipped", "no instances", "unavailable"} {
		t.Run(variant, func(t *testing.T) {
			var mu sync.Mutex
			plans, updates := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/plan") {
					updates++
					io.WriteString(w, `{"results":[]}`)
					return
				}
				plans++
				switch variant {
				case "foreign ID rejected":
					w.WriteHeader(http.StatusBadRequest)
					io.WriteString(w, `{"error":"instance does not belong to project"}`)
				case "unavailable":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "no instances":
					io.WriteString(w, `{"read_only":true,"project_id":"project-1","eligible_count":0,"skipped_count":0,"failed_count":0,"results":[]}`)
				case "all skipped":
					io.WriteString(w, `{"read_only":true,"project_id":"project-1","eligible_count":0,"skipped_count":1,"failed_count":0,"results":[{"instance_id":"`+testContainerID+`","name":"app","status":"skipped","plan":null,"error":"already updating"}]}`)
				default:
					writeTestUpdatePlan(t, w, r, testContainerID, "project-1", updateStrategyBlueGreen)
				}
			}))
			defer server.Close()
			args := []string{"project", "update", "acme/app", "--tag", "v2", "--yes", "-o", "json"}
			if strings.HasPrefix(variant, "foreign ID") {
				args = append(args, "--instance", testContainerID, "--instance", "foreign")
			} else if variant == "unselected ID returned" {
				args = append(args, "--instance", "foreign")
			}
			out, err := consentCLIProcess(t, server.URL, args...).CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if err == nil || plans != 1 || updates != 0 {
				t.Fatalf("invalid initial plan executed: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
			}
		})
	}
}

func TestUpdateRecheckIgnoresUnreviewedMetadata(t *testing.T) {
	var mu sync.Mutex
	plans, updates := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"id":"`+testContainerID+`"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/plan") {
			plans++
			var plan map[string]any
			if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
				t.Error(err)
				return
			}
			plan["updated_at"] = fmt.Sprintf("2026-09-24T00:00:%02dZ", plans)
			plan["generated_at"] = plans
			json.NewEncoder(w).Encode(plan)
			return
		}
		updates++
		io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
	}))
	defer server.Close()
	out, err := consentCLIProcess(t, server.URL, "container", "update", testContainerID, "--tag", "v2", "--no-wait").CombinedOutput()
	mu.Lock()
	defer mu.Unlock()
	if err != nil || plans != 2 || updates != 1 || strings.Contains(string(out), "fresh confirmation") {
		t.Fatalf("irrelevant metadata changed consent: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
	}
}

func TestDowntimeRefusalReplansBeforeRenewedConsent(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, variant := range []string{"approve", "decline", "plan failure", "inconsistent strategy", "hold unavailable"} {
			t.Run(fmt.Sprintf("project=%t/%s", project, variant), func(t *testing.T) {
				var mu sync.Mutex
				plans, posts := 0, 0
				changedDuringPrompt := false
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					if r.Method == http.MethodGet {
						if project {
							io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
						} else {
							io.WriteString(w, `{"id":"`+testContainerID+`"}`)
						}
						return
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						return
					}
					if body["hold"] != (variant == "hold unavailable") || body["mark_latest_release"] != false {
						t.Errorf("explicit overrides changed: %v", body)
					}
					if project && plans > 0 && !reflect.DeepEqual(body["instance_ids"], []any{testContainerID}) {
						t.Errorf("fallback selection changed: %v", body)
					}
					if strings.HasSuffix(r.URL.Path, "/plan") {
						plans++
						if body["confirm_downtime"] == true {
							t.Error("consent reused in planning")
						}
						if posts > 0 && variant == "plan failure" {
							w.WriteHeader(http.StatusForbidden)
							io.WriteString(w, `{"error":"planning denied"}`)
							return
						}
						var plan updatePlan
						if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
							t.Error(err)
							return
						}
						plan.Hold, plan.HoldSource, plan.MarkLatestRelease = variant == "hold unavailable", "request", false
						if posts > 0 && variant != "inconsistent strategy" {
							plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = updateStrategyReplace, true, false
							plan.Target.CPUs = 8
							if changedDuringPrompt {
								plan.Target.CPUs = 16
								plan.ConfigurationChanges.Settings = []string{"custom_domain"}
							}
						}
						var response any = plan
						if project {
							response = map[string]any{"read_only": true, "project_id": "project-1", "eligible_count": 1, "skipped_count": 0, "failed_count": 0, "results": []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan}}}
						}
						json.NewEncoder(w).Encode(response)
						return
					}
					posts++
					if posts == 1 {
						if body["confirm_downtime"] == true {
							t.Error("initial blue/green request granted downtime consent")
						}
						w.WriteHeader(http.StatusConflict)
						io.WriteString(w, `{"code":"DOWNTIME_CONFIRMATION_REQUIRED","error":"target requires replacement"}`)
						return
					}
					if !changedDuringPrompt || body["confirm_downtime"] != true || plans != 5 {
						t.Errorf("retry without fresh consent and recheck: plans=%d body=%v", plans, body)
					}
					if project {
						io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","name":"app","status":"updating"}]}`)
					} else {
						io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
					}
				}))
				defer server.Close()
				args := []string{"container", "update", testContainerID, "--tag", "v2", "--no-wait"}
				if project {
					args = []string{"project", "update", "acme/app", "--tag", "v2"}
				}
				args = append(args, "--hold="+boolText(variant == "hold unavailable"), "--mark-latest=false")
				cmd := consentCLIProcess(t, server.URL, args...)
				out, prompts, err := runConsentTTY(t, cmd, func(prompt int) string {
					mu.Lock()
					defer mu.Unlock()
					if posts != 1 {
						t.Error("mutation retried while awaiting consent")
					}
					changedDuringPrompt = true
					if prompt > 1 && variant == "decline" {
						return "no\n"
					}
					return "yes\n"
				})
				mu.Lock()
				defer mu.Unlock()
				wantPosts, wantPlans, wantPrompts, wantMessage := 1, 3, 0, ""
				switch variant {
				case "approve":
					wantPosts, wantPlans, wantPrompts, wantMessage = 2, 5, 2, "Changed settings: custom_domain"
				case "decline":
					wantPlans, wantPrompts, wantMessage = 4, 2, "aborted"
				case "plan failure":
					wantMessage = "planning denied"
				case "inconsistent strategy":
					wantMessage = "no retry was sent"
				case "hold unavailable":
					wantMessage = "pass --hold=false"
				}
				if posts != wantPosts || plans != wantPlans || prompts != wantPrompts || !strings.Contains(out, wantMessage) {
					t.Fatalf("unsafe fallback: plans=%d posts=%d prompts=%d err=%v\n%s", plans, posts, prompts, err, out)
				}
				if wantPrompts > 0 && (!strings.Contains(out, "CPU: 2 -> 8") || !strings.Contains(out, "CPU: 2 -> 16")) {
					t.Fatalf("changed retry target was not presented: %s", out)
				}
			})
		}
	}
}
