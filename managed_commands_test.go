package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestManagedCreateCommandNeedsOnlyPublicKeyAndClearsCompletedIntent(t *testing.T) {
	p, _ := managedTestIntent(t, "monitor")
	key, err := measuredOwner(p.Owner)
	require.NoError(t, err)
	publicFile := filepath.Join(t.TempDir(), "owner.pub")
	require.NoError(t, os.WriteFile(publicFile, ssh.MarshalAuthorizedKey(key), 0600))
	var row containerView
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers":
			json.NewEncoder(w).Encode([]containerView{})
		case "POST /api/containers":
			posts++
			var body struct {
				Name, Tag string
				Variables map[string]string
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "personal", body.Name)
			require.Equal(t, "v7", body.Tag)
			require.Equal(t, p.Owner, body.Variables[monitorOwnerEnv])
			p.Name, p.Tag = body.Name, body.Tag
			row = managedTestRow(t, p)
			json.NewEncoder(w).Encode(row)
		case "GET /api/containers/" + testContainerID:
			json.NewEncoder(w).Encode(row)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	oldIdentity := attestSSHIdentity
	attestSSHIdentity = ""
	t.Cleanup(func() { attestSSHIdentity = oldIdentity })
	cmd := newManagedCreateCmd("monitor")
	cmd.SetContext(context.Background())
	require.NoError(t, cmd.ParseFlags([]string{"personal", "--tag", "v7", "--owner-public-key", publicFile}))
	_, err = captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
	require.NoError(t, err)
	require.Equal(t, 1, posts)
	p.Scope.ControlplaneURL = server.URL
	path, err := pendingCreationPath(p.Scope)
	require.NoError(t, err)
	require.NoFileExists(t, path)
	require.NoFileExists(t, path+".lock")
	files, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Empty(t, files, "creation must not generate custody/private keys")
}

func TestManagedRestartAbortsIfConfigurationChangesWhileStopping(t *testing.T) {
	p, _ := managedTestIntent(t, "monitor")
	row := managedTestRow(t, p)
	oldInterval := followInterval
	followInterval = 0
	t.Cleanup(func() { followInterval = oldInterval })
	client := newCPClient(cliConfig{ControlplaneURL: p.Scope.ControlplaneURL})
	client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			require.True(t, strings.HasSuffix(r.URL.Path, "/stop"), "must never deploy after concurrent modification")
			row.Status = statusStopping
		} else {
			row.Status, row.CurrentTag = statusStopped, "v9"
		}
		return managedTestResponse(t, row), nil
	})
	_, err := stopContainer(client, row)
	require.ErrorContains(t, err, "changed while stopping")
}

func TestManagedCreationCancellationPreservesPendingIntent(t *testing.T) {
	p, path := managedTestIntent(t, "monitor")
	p.ID, p.Submitted = testContainerID, true
	require.NoError(t, writeStorageJSON(path, p, false))
	row := managedTestRow(t, p)
	row.Status = statusCreated
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newCPClient(cliConfig{ControlplaneURL: p.Scope.ControlplaneURL})
	client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) { cancel(); return managedTestResponse(t, row), nil })
	_, complete, err := provisionManaged(ctx, client, path, &p, false, io.Discard)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, complete)
	saved, err := readPendingCreation(path, p.Scope)
	require.NoError(t, err)
	require.Equal(t, p, saved)
}

func TestManagedDetailIncludesAttemptErrorAndNestedStageDetails(t *testing.T) {
	previous := outputFormat
	outputFormat = "table"
	t.Cleanup(func() { outputFormat = previous })
	var row containerView
	require.NoError(t, json.Unmarshal([]byte(`{"status":"stopped","config_name":"config-digest","current_tag":"v7","error_message":"old failure","last_deploy_attempt_error":"approval has expired","boot_stages":[{"name":"parent","stages":[{"name":"disk","status":"failed","detail":"disk busy"}]}]}`), &row))
	output, err := captureTestStdout(func() error { return renderContainer(row) })
	require.NoError(t, err)
	for _, text := range []string{"v7", "approval has expired", "disk busy"} {
		require.Contains(t, string(output), text)
	}
	require.NotContains(t, string(output), "old failure")
	require.NotContains(t, string(output), "parent")
}

func TestSandboxStartWithoutEnrollmentNeedsNoLocalOwnerKey(t *testing.T) {
	p, _ := managedTestIntent(t, "sandbox")
	row := managedTestRow(t, p)
	row.Status = statusStopped
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/containers/" + row.ID:
			json.NewEncoder(w).Encode(row)
		case "POST /api/containers/" + row.ID + "/deploy":
			posts++
			row.Status = statusRunning
			json.NewEncoder(w).Encode(row)
		default:
			t.Errorf("unexpected connection/enrollment request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	flag := sandboxStartCmd.Flags().Lookup("no-enroll")
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() { _ = flag.Value.Set(previous); flag.Changed = changed })
	require.NoError(t, sandboxStartCmd.Flags().Set("no-enroll", "true"))
	_, err := captureTestStdout(func() error { return sandboxStartCmd.RunE(sandboxStartCmd, []string{row.ID}) })
	require.NoError(t, err)
	require.Equal(t, 1, posts)
}

type managedStatusWriter func([]byte) (int, error)

func (write managedStatusWriter) Write(p []byte) (int, error) { return write(p) }

func TestManagedStatusWatchesTransitionsAndCancels(t *testing.T) {
	p, _ := managedTestIntent(t, "monitor")
	row := managedTestRow(t, p)
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET /api/containers/"+row.ID, r.Method+" "+r.URL.Path)
		states := []string{statusCreated, statusDeploying, statusRunning}
		row.Status = states[min(reads, len(states)-1)]
		reads++
		json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	outputFormat = "table"
	previous := followInterval
	followInterval = time.Millisecond
	t.Cleanup(func() { followInterval = previous })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := newManagedStatusCmd("monitor")
	cmd.SetContext(ctx)
	cmd.SetOut(managedStatusWriter(func(p []byte) (int, error) {
		if strings.Contains(string(p), "The VM is running") {
			cancel()
		}
		return len(p), nil
	}))
	require.NoError(t, cmd.Flags().Set("watch", "true"))
	output, err := captureTestStdout(func() error { return cmd.RunE(cmd, []string{row.ID}) })
	require.NoError(t, err)
	for _, state := range []string{"Created", "Deploying", "Running"} {
		require.Contains(t, string(output), state)
	}
	require.Equal(t, 3, reads)
}

func TestManagedStatusListsOnlyRequestedProductionKind(t *testing.T) {
	rows := []containerView{{ID: "sandbox", Repo: defaultSandboxRepo}, {ID: "monitor", Repo: monitorRepo}, {ID: "debug", Repo: monitorRepo, Debug: true}, {ID: "other", Repo: "acme/other"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/containers", r.URL.Path)
		json.NewEncoder(w).Encode(rows)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	outputFormat = "json"
	for _, kind := range []string{"sandbox", "monitor", "container"} {
		for _, verb := range []string{"status", "get", "list", "ls"} {
			if kind == "container" && verb != "list" {
				continue
			}
			t.Run(kind+"/"+verb, func(t *testing.T) {
				output, err := captureTestStdout(func() error { return executeLifecycleCLI(t, kind, verb) })
				require.NoError(t, err)
				var listed []containerView
				require.NoError(t, json.Unmarshal(output, &listed))
				if kind == "container" {
					require.Len(t, listed, len(rows))
				} else {
					require.Len(t, listed, 1)
					require.Equal(t, kind, listed[0].ID)
				}
			})
		}
	}
}

func TestManagedCommandAliasesRejectOtherKindsAndDebugResources(t *testing.T) {
	for _, command := range [][]string{{"monitor", "start"}, {"monitor", "stop"}, {"monitor", "rm", "--yes"}, {"monitor", "update", "--yes"}, {"sandbox", "update", "--yes"}} {
		for _, debug := range []bool{false, true} {
			t.Run(strings.Join(command, " ")+"/debug="+strconv.FormatBool(debug), func(t *testing.T) {
				row := containerView{ID: testContainerID, Name: "work", Repo: "other/repo"}
				if debug {
					row.Repo, row.Debug = managedRepo(command[0]), true
				}
				mutations := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						mutations++
						http.Error(w, "unexpected mutation", http.StatusBadRequest)
					} else if r.URL.Path == "/api/containers" {
						json.NewEncoder(w).Encode([]containerView{row})
					} else {
						json.NewEncoder(w).Encode(row)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				err := executeLifecycleCLI(t, append(append([]string{}, command...), "work")...)
				require.ErrorContains(t, err, "not a production "+command[0])
				require.Zero(t, mutations)
			})
		}
	}
}

func TestMonitorAliasesUseExistingLifecycleRequests(t *testing.T) {
	for _, action := range []string{"start", "stop", "delete"} {
		t.Run(action, func(t *testing.T) {
			row := containerView{ID: testContainerID, Name: "personal", Repo: monitorRepo, Status: statusStopped}
			var mutations []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if len(mutations) != 0 {
						t.Error("unexpected polling after the lifecycle response")
						http.Error(w, "unexpected polling", http.StatusBadRequest)
						return
					}
					if r.URL.Path == "/api/containers" {
						json.NewEncoder(w).Encode([]containerView{row})
					} else {
						json.NewEncoder(w).Encode(row)
					}
					return
				}
				mutations = append(mutations, r.Method+" "+r.URL.Path)
				if action == "start" {
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Empty(t, body, "start must retain the saved configuration")
					row.Status = statusDeploying
				}
				json.NewEncoder(w).Encode(row)
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			args := []string{"monitor", action, "personal", "--output", "table"}
			want := "POST /api/containers/" + row.ID + "/" + action
			if action == "start" {
				args = append(args, "--no-wait")
				want = "POST /api/containers/" + row.ID + "/deploy"
			} else if action == "delete" {
				args = append(args, "--yes")
				want = "DELETE /api/containers/" + row.ID
			}
			output, err := captureTestStdout(func() error { return executeLifecycleCLI(t, args...) })
			require.NoError(t, err)
			require.Equal(t, []string{want}, mutations)
			if action == "stop" {
				require.Contains(t, string(output), "tinfoil monitor start personal")
			}
			require.False(t, containerDeployCmd.Flags().Changed("no-wait"))
			require.False(t, containerDeleteCmd.Flags().Changed("yes"))
		})
	}
}

func TestManagedUpdateAliasesKeepPlanReviewAndDowntimeConsent(t *testing.T) {
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	previous := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = previous; stdin.Close() })
	for _, kind := range []string{"sandbox", "monitor"} {
		for _, scenario := range []string{"confirmed", "unconfirmed", "plan unavailable"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				row := containerView{ID: testContainerID, Name: "work", Repo: managedRepo(kind), Status: statusRunning}
				var requests []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						json.NewEncoder(w).Encode(row)
						return
					}
					requests = append(requests, r.URL.Path)
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "v2", body["tag"])
					require.Equal(t, false, body["hold"], "managed updates switch automatically")
					if strings.HasSuffix(r.URL.Path, "/plan") {
						if scenario == "plan unavailable" {
							http.Error(w, "plan unavailable", http.StatusServiceUnavailable)
							return
						}
						var plan updatePlan
						require.NoError(t, json.Unmarshal([]byte(updatePlanFixture), &plan))
						plan.UpdateStrategy, plan.DowntimeRequired, plan.HoldAvailable = updateStrategyReplace, true, false
						plan.HoldSource = "request"
						json.NewEncoder(w).Encode(plan)
					} else {
						require.Equal(t, true, body["confirm_downtime"])
						json.NewEncoder(w).Encode(row)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				args := []string{kind, "update", row.ID, "--tag", "v2", "--no-wait"}
				if scenario != "unconfirmed" {
					args = append(args, "--yes")
				}
				stderr, err := captureTestStderr(func() error {
					_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, args...) })
					return err
				})
				planPath := "/api/containers/" + row.ID + "/update/plan"
				if scenario == "confirmed" {
					require.NoError(t, err)
					require.Equal(t, []string{planPath, planPath, strings.TrimSuffix(planPath, "/plan")}, requests)
					require.Contains(t, string(stderr), "downtime")
				} else {
					require.Error(t, err)
					require.Equal(t, []string{planPath}, requests, "must not mutate without a reviewed, approved plan")
				}
				require.False(t, containerUpdateCmd.Flags().Changed("tag"))
				require.False(t, containerUpdateCmd.Flags().Changed("yes"))
			})
		}
	}
}
