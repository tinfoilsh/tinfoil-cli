package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func secretDeliveryPlanFixture(t *testing.T, mode string) map[string]any {
	t.Helper()
	var plan map[string]any
	if err := json.Unmarshal([]byte(updatePlanFixture), &plan); err != nil {
		t.Fatal(err)
	}
	if mode == "" {
		return plan
	}
	managed, external := []string{"TOKEN"}, []string{}
	if mode == secretDeliveryPrivateKeyserver {
		managed, external = []string{}, []string{"API_KEY", "MODEL_KEY", "VOLUME_KEY"}
		plan["configuration_changes"].(map[string]any)["secrets_refreshed"] = managed
	}
	plan["secret_delivery"] = map[string]any{
		"mode": mode, "managed_secrets": managed, "external_secrets": external,
		"external_secrets_verified": false, "keyserver_ignored_in_debug": mode == secretDeliveryManaged,
	}
	return plan
}

func writeSecretDeliveryPlan(t *testing.T, w http.ResponseWriter, plan map[string]any, project bool) {
	t.Helper()
	var response any = plan
	if project {
		response = map[string]any{"read_only": true, "project_id": "project-1", "eligible_count": 1, "skipped_count": 0, "failed_count": 0,
			"results": []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "planned", "plan": plan}}}
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.Error(err)
	}
}

func TestSecretDeliveryPlanOutput(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, mode := range []string{"", secretDeliveryPrivateKeyserver, secretDeliveryManaged} {
			for _, format := range []string{"table", "json"} {
				t.Run(fmt.Sprintf("project=%t/%s/%s", project, mode, format), func(t *testing.T) {
					plan := secretDeliveryPlanFixture(t, mode)
					if mode != "" {
						delivery := plan["secret_delivery"].(map[string]any)
						delivery["keyserver_url"] = "https://credential-never-print@private.example"
						delivery["secret_value"] = "secret-value-never-print"
					}
					var mu sync.Mutex
					plans, updates := 0, 0
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						defer mu.Unlock()
						switch {
						case r.Method == http.MethodGet && project:
							io.WriteString(w, `[{"id":"project-1","repo":"acme/app"}]`)
						case r.Method == http.MethodGet:
							io.WriteString(w, `{"id":"`+testContainerID+`"}`)
						case strings.HasSuffix(r.URL.Path, "/plan"):
							plans++
							writeSecretDeliveryPlan(t, w, plan, project)
						default:
							updates++
							if project {
								io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","status":"updating"}]}`)
							} else {
								io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
							}
						}
					}))
					defer server.Close()
					args := []string{"container", "update", testContainerID, "--no-wait"}
					if project {
						args = []string{"project", "update", "acme/app", "--tag", "v2"}
					}
					cmd := consentCLIProcess(t, server.URL, append(args, "-o", format)...)
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					stdout, err := cmd.Output()
					mu.Lock()
					defer mu.Unlock()
					if err != nil || updates != 1 || plans != 2 {
						t.Fatalf("plan execution: plans=%d updates=%d err=%v\n%s", plans, updates, err, stderr.String())
					}
					for _, forbidden := range []string{"credential-never-print", "private.example", "secret-value-never-print"} {
						if strings.Contains(string(stdout)+stderr.String(), forbidden) {
							t.Fatalf("plan leaked %s", forbidden)
						}
					}
					if format == "json" {
						if !json.Valid(stdout) || !json.Valid(stderr.Bytes()) {
							t.Fatalf("invalid JSON stdout=%s stderr=%s", stdout, stderr.String())
						}
						if (mode != "") != strings.Contains(stderr.String(), `"secret_delivery"`) {
							t.Fatalf("optional metadata not preserved: %s", stderr.String())
						}
						if mode != "" && !strings.Contains(stderr.String(), `"external_secrets_verified":false`) {
							t.Fatal("lost verification boundary")
						}
						return
					}
					wants := []string{"Refresh current secret values: TOKEN"}
					if mode == secretDeliveryPrivateKeyserver {
						wants = []string{"Managed secrets: none", "External secrets: API_KEY, MODEL_KEY, VOLUME_KEY", "Private keyserver delivery; authorization and unlock are not verified here"}
						if strings.Contains(stderr.String(), "Refresh current secret values: none") {
							t.Fatal("private secrets were described as no secrets")
						}
					} else if mode == secretDeliveryManaged {
						wants = []string{"Managed secrets: TOKEN", "External secrets: none", "private keyserver endpoint ignored in debug mode"}
					}
					for _, want := range wants {
						if !strings.Contains(stderr.String(), want) {
							t.Fatalf("missing %q: %s", want, stderr.String())
						}
					}
				})
			}
		}
	}
}

func TestSecretDeliveryInvalidPlansFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"unknown mode", "mode", "unknown"},
		{"empty mode", "mode", ""},
		{"wrong mode type", "mode", true},
		{"null names", "external_secrets", nil},
		{"wrong names type", "external_secrets", "VALUE"},
		{"object instead of name", "external_secrets", []any{map[string]string{"API_KEY": "never-print"}}},
		{"empty name", "external_secrets", []string{""}},
		{"endpoint instead of name", "external_secrets", []string{"https://credential-never-print@private.example"}},
		{"value instead of name", "external_secrets", []string{"KEY=never-print"}},
		{"unverified boundary", "external_secrets_verified", true},
		{"wrong verified type", "external_secrets_verified", "never-print"},
		{"inconsistent debug mode", "keyserver_ignored_in_debug", true},
		{"mixed delivery", "managed_secrets", []string{"TOKEN"}},
	} {
		for _, project := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/project=%t", tc.name, project), func(t *testing.T) {
				plan := secretDeliveryPlanFixture(t, secretDeliveryPrivateKeyserver)
				plan["secret_delivery"].(map[string]any)[tc.field] = tc.value
				var mu sync.Mutex
				updates := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					if strings.HasSuffix(r.URL.Path, "/plan") {
						if project {
							good := secretDeliveryPlanFixture(t, "")
							good["instance_id"] = "other"
							json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "eligible_count": 2, "results": []any{
								map[string]any{"instance_id": "other", "status": "planned", "plan": good},
								map[string]any{"instance_id": testContainerID, "status": "planned", "plan": plan},
							}})
						} else {
							writeSecretDeliveryPlan(t, w, plan, false)
						}
						return
					}
					updates++
				}))
				defer server.Close()
				client := &cpClient{baseURL: server.URL, http: server.Client()}
				var err error
				if project {
					_, err = updateProjectInstances(client, "project-1", map[string]any{"tag": "v2"})
				} else {
					err = postLifecycleUpdate(client, "/update", map[string]any{}, nil, true, "update", func() (updateReview, error) {
						return planContainerUpdate(client, testContainerID, map[string]any{})
					})
				}
				mu.Lock()
				defer mu.Unlock()
				if err == nil || updates != 0 || strings.Contains(err.Error(), "never-print") {
					t.Fatalf("invalid plan not safely rejected: updates=%d err=%v", updates, err)
				}
			})
		}
	}
}

func TestSecretDeliveryReviewSemantics(t *testing.T) {
	decode := func(mode string) updatePlan {
		data, err := json.Marshal(secretDeliveryPlanFixture(t, mode))
		if err != nil {
			t.Fatal(err)
		}
		var plan updatePlan
		if err := json.Unmarshal(data, &plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	left, right := decode(""), decode(secretDeliveryManaged)
	right.SecretDelivery.KeyserverIgnoredInDebug = false
	equal := func() bool {
		return sameUpdateReview(updateReview{plans: []updatePlan{left}}, updateReview{plans: []updatePlan{right}})
	}
	if !equal() || left.SecretDelivery != nil {
		t.Fatal("optional managed metadata caused drift or mutated baseline")
	}
	right.SecretDelivery.KeyserverIgnoredInDebug = true
	if equal() {
		t.Fatal("ignored-endpoint change did not require review")
	}
	left, right = decode(secretDeliveryPrivateKeyserver), decode(secretDeliveryPrivateKeyserver)
	right.SecretDelivery.ExternalSecrets = []string{"VOLUME_KEY", "MODEL_KEY", "API_KEY"}
	if !equal() || right.SecretDelivery.ExternalSecrets[0] != "VOLUME_KEY" {
		t.Fatal("name order caused drift or comparison mutated display")
	}
	right.SecretDelivery.ExternalSecrets = []string{"NEW_KEY"}
	if equal() {
		t.Fatal("external declaration change ignored")
	}
	right = decode("")
	right.ConfigurationChanges.SecretsRefreshed = []string{}
	left.SecretDelivery.ExternalSecrets = []string{}
	if equal() {
		t.Fatal("delivery mode change ignored with empty secret lists")
	}
}

func TestSecretSelectionFlagBodies(t *testing.T) {
	for _, command := range []string{"create", "deploy", "update"} {
		for _, tc := range []struct {
			name  string
			flags []string
			want  any
			valid bool
		}{
			{"omitted", nil, nil, true},
			{"clear", []string{"--secret="}, []any{}, true},
			{"selected", []string{"--secret=FIRST", "--secret=SECOND"}, []any{"FIRST", "SECOND"}, true},
			{"mixed", []string{"--secret=", "--secret=TOKEN"}, nil, false},
			{"mixed reversed", []string{"--secret=TOKEN", "--secret="}, nil, false},
			{"repeated empty", []string{"--secret=", "--secret="}, nil, false},
			{"whitespace", []string{"--secret= "}, nil, false},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				var mu sync.Mutex
				requests, mutations := 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					requests++
					if r.Method == http.MethodGet {
						io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
						return
					}
					if strings.HasSuffix(r.URL.Path, "/validate") {
						io.WriteString(w, `{"valid":true,"config":{}}`)
						return
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						return
					}
					value, present := body["secrets"]
					if !reflect.DeepEqual(value, tc.want) || present != (tc.flags != nil) {
						t.Errorf("incorrect secret selection: %#v, want %#v (present=%t)", body, tc.want, present)
					}
					if strings.HasSuffix(r.URL.Path, "/plan") {
						writeSecretDeliveryPlan(t, w, secretDeliveryPlanFixture(t, ""), false)
						return
					}
					mutations++
					io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
				}))
				defer server.Close()
				args := []string{"container", command, testContainerID, "--no-wait", "--yes", "-o", "json"}
				if command == "deploy" {
					args = []string{"container", command, testContainerID, "--no-wait", "-o", "json"}
				} else if command == "create" {
					args = append(args, "--repo", "acme/app", "--tag", "v2")
				}
				out, err := consentCLIProcess(t, server.URL, append(args, tc.flags...)...).CombinedOutput()
				mu.Lock()
				defer mu.Unlock()
				if tc.valid && (err != nil || mutations != 1) || !tc.valid && (err == nil || requests != 0 || !strings.Contains(string(out), "--secret")) {
					t.Fatalf("selection validation: requests=%d mutations=%d err=%v\n%s", requests, mutations, err, out)
				}
			})
		}
	}
}

func TestSecretDeliveryChangesRequireConsent(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, change := range []string{"mode", "external names", "debug ignores endpoint"} {
			for _, approval := range []string{"no", "yes", "automatic"} {
				t.Run(fmt.Sprintf("project=%t/%s/%s", project, change, approval), func(t *testing.T) {
					var mu sync.Mutex
					changed := false
					plans, updates := 0, 0
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
						if !strings.HasSuffix(r.URL.Path, "/plan") {
							updates++
							if project {
								io.WriteString(w, `{"results":[{"container_id":"`+testContainerID+`","status":"updating"}]}`)
							} else {
								io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
							}
							return
						}
						plans++
						if approval == "automatic" && plans > 1 {
							changed = true
						}
						plan := secretDeliveryPlanFixture(t, secretDeliveryPrivateKeyserver)
						switch change {
						case "mode":
							plan["secret_delivery"].(map[string]any)["external_secrets"] = []string{}
							if !changed {
								delete(plan, "secret_delivery")
							}
						case "external names":
							if changed {
								plan["secret_delivery"].(map[string]any)["external_secrets"] = []string{"NEW_KEY"}
							}
						case "debug ignores endpoint":
							plan = secretDeliveryPlanFixture(t, secretDeliveryManaged)
							plan["secret_delivery"].(map[string]any)["keyserver_ignored_in_debug"] = changed
						}
						plan["update_strategy"], plan["downtime_required"], plan["hold_available"] = updateStrategyReplace, true, false
						writeSecretDeliveryPlan(t, w, plan, project)
					}))
					defer server.Close()
					args := []string{"container", "update", testContainerID, "--no-wait"}
					if project {
						args = []string{"project", "update", "acme/app", "--tag", "v2"}
					}
					var out string
					var err error
					if approval == "automatic" {
						data, runErr := consentCLIProcess(t, server.URL, append(args, "--yes")...).CombinedOutput()
						out, err = string(data), runErr
					} else {
						var prompts int
						out, prompts, err = runConsentTTY(t, consentCLIProcess(t, server.URL, args...), func(prompt int) string {
							mu.Lock()
							defer mu.Unlock()
							if updates != 0 {
								t.Error("mutation before renewed delivery consent")
							}
							changed = true
							if prompt == 1 {
								return "yes\n"
							}
							return approval + "\n"
						})
						if prompts != 2 {
							t.Fatalf("expected renewed consent, prompts=%d\n%s", prompts, out)
						}
					}
					mu.Lock()
					defer mu.Unlock()
					if approval == "no" {
						if updates != 0 || plans != 2 || !strings.Contains(out, "aborted") {
							t.Fatalf("declined delivery executed: plans=%d updates=%d\n%s", plans, updates, out)
						}
					} else if err != nil || updates != 1 || plans != 3 {
						t.Fatalf("renewed review failed: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
					}
					want := "Private keyserver delivery; authorization and unlock are not verified here"
					if change == "external names" {
						want = "External secrets: NEW_KEY"
					} else if change == "debug ignores endpoint" {
						want = "private keyserver endpoint ignored in debug mode"
					}
					if !strings.Contains(out, want) || !strings.Contains(out, "fresh confirmation is required") {
						t.Fatalf("delivery change not reviewed: %s", out)
					}
					if approval == "automatic" && !strings.Contains(out, "Accepting the displayed update plan automatically (--yes)") {
						t.Fatal("automatic consent not explicit")
					}
				})
			}
		}
	}
}

func TestSecretDeliveryOptionalMetadataDoesNotCauseReconfirmation(t *testing.T) {
	for _, startsExplicit := range []bool{false, true} {
		t.Run(boolText(startsExplicit), func(t *testing.T) {
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
					plan := secretDeliveryPlanFixture(t, secretDeliveryManaged)
					plan["secret_delivery"].(map[string]any)["keyserver_ignored_in_debug"] = false
					if startsExplicit != (plans == 1) {
						delete(plan, "secret_delivery")
					}
					writeSecretDeliveryPlan(t, w, plan, false)
					return
				}
				updates++
				io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
			}))
			defer server.Close()
			out, err := consentCLIProcess(t, server.URL, "container", "update", testContainerID, "--no-wait").CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if err != nil || updates != 1 || plans != 2 || strings.Contains(string(out), "fresh confirmation") {
				t.Fatalf("optional metadata caused drift: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
			}
		})
	}
}

func TestPrivateSecretSelectionFailureGuidance(t *testing.T) {
	for _, project := range []bool{false, true} {
		for _, format := range []string{"table", "json"} {
			t.Run(fmt.Sprintf("project=%t/%s", project, format), func(t *testing.T) {
				var mu sync.Mutex
				updates := 0
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
					if !strings.HasSuffix(r.URL.Path, "/plan") {
						updates++
						return
					}
					if project {
						json.NewEncoder(w).Encode(map[string]any{"read_only": true, "project_id": "project-1", "failed_count": 1,
							"results": []any{map[string]any{"instance_id": testContainerID, "name": "app", "status": "failed", "error": privateSecretSelectionConflict}}})
					} else {
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]string{"error": privateSecretSelectionConflict})
					}
				}))
				defer server.Close()
				args := []string{"container", "update", testContainerID, "--no-wait"}
				if project {
					args = []string{"project", "update", "acme/app", "--tag", "v2"}
				}
				out, err := consentCLIProcess(t, server.URL, append(args, "--yes", "-o", format)...).CombinedOutput()
				mu.Lock()
				defer mu.Unlock()
				if err == nil || updates != 0 || !strings.Contains(string(out), "--secret=") || !strings.Contains(string(out), "migrate affected instances individually first") {
					t.Fatalf("missing safe recovery: updates=%d err=%v\n%s", updates, err, out)
				}
			})
		}
	}
	message := secretDeliveryMessage(privateSecretSelectionConflict)
	if secretDeliveryMessage(message) != message || secretDeliveryMessage("permission denied") != "permission denied" {
		t.Fatal("recovery hint duplicated or masked unrelated error")
	}
}

func TestPrivateMigrationRequiresExplicitClearing(t *testing.T) {
	for _, flag := range []string{"", "--secret=", "--secret=API_KEY"} {
		t.Run(flag, func(t *testing.T) {
			var mu sync.Mutex
			plans, updates := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"id":"`+testContainerID+`","secrets":["SAVED_MANAGED_KEY"]}`)
					return
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/plan") {
					plans++
					if !reflect.DeepEqual(body["secrets"], []any{}) {
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]string{"error": privateSecretSelectionConflict})
						return
					}
					writeSecretDeliveryPlan(t, w, secretDeliveryPlanFixture(t, secretDeliveryPrivateKeyserver), false)
					return
				}
				updates++
				if !reflect.DeepEqual(body["secrets"], []any{}) {
					t.Errorf("explicit clearing lost in execution: %v", body)
				}
				io.WriteString(w, `{"id":"`+testContainerID+`","status":"running"}`)
			}))
			defer server.Close()
			args := []string{"container", "update", testContainerID, "--tag", "v2", "--no-wait"}
			if flag != "" {
				args = append(args, flag)
			}
			out, err := consentCLIProcess(t, server.URL, args...).CombinedOutput()
			mu.Lock()
			defer mu.Unlock()
			if flag == "--secret=" {
				if err != nil || plans != 2 || updates != 1 || !strings.Contains(string(out), "External secrets: API_KEY, MODEL_KEY, VOLUME_KEY") {
					t.Fatalf("explicit migration failed: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
				}
			} else if err == nil || plans != 1 || updates != 0 || !strings.Contains(string(out), `--secret=""`) {
				t.Fatalf("implicit migration was not refused: plans=%d updates=%d err=%v\n%s", plans, updates, err, out)
			}
		})
	}
}
