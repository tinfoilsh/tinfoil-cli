package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func managedTestAPI(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	configureContainerPromotionTest(t, server.URL)
}

func TestManagedAliasesRejectWrongKindBeforeMutation(t *testing.T) {
	row := containerView{ID: testContainerID, Name: "work"}
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		json.NewEncoder(w).Encode(row)
	})
	for _, kind := range []string{"sandbox", "monitor"} {
		for _, verb := range []string{"start", "stop", "delete", "update", "metrics"} {
			for _, debug := range []bool{false, true} {
				row.Repo, row.Debug = "other/repo", debug
				if debug {
					row.Repo = managedRepo(kind)
				}
				require.Error(t, executeLifecycleCLI(t, kind, verb, row.ID))
			}
		}
	}
}

func TestManagedMetricsUseTheChosenWindow(t *testing.T) {
	row := containerView{ID: testContainerID, Name: "work", Repo: defaultSandboxRepo}
	window := ""
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/containers/" + row.ID:
			json.NewEncoder(w).Encode(row)
		case "GET /api/containers/" + row.ID + "/metrics":
			window = r.URL.Query().Get("time")
			w.Write([]byte(`{"data_points":[]}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	out, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "sandbox", "metrics", row.ID, "--time", "1h") })
	require.NoError(t, err)
	require.Equal(t, "1h", window)
	require.Contains(t, string(out), `"data_points"`)
}

func TestMonitorStopAndDeleteIncludeItsSandboxes(t *testing.T) {
	const otherMonitorID = "33333333-3333-4333-8333-333333333333"
	monitor := containerView{ID: testContainerID, Name: "mon", Repo: monitorRepo, ClerkUserID: "owner", Status: statusRunning}
	routed := func(id, name, repo, user, monitorID string) containerView {
		policy := sandboxNetworkPolicy(monitorID)
		return containerView{ID: id, Name: name, Repo: repo, ClerkUserID: user, NetworkPolicy: &policy}
	}
	work := routed("11111111-1111-4111-8111-111111111111", "work", defaultSandboxRepo, "owner", monitor.ID)
	other := routed("22222222-2222-4222-8222-222222222222", "other", defaultSandboxRepo, "owner", otherMonitorID)
	var mutations []string
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers":
			json.NewEncoder(w).Encode([]containerView{monitor, work, other,
				routed("44444444-4444-4444-8444-444444444444", "member", defaultSandboxRepo, "member", monitor.ID),
				routed("55555555-5555-4555-8555-555555555555", "app", "acme/app", "owner", monitor.ID)})
		case "GET /api/containers/" + monitor.ID:
			json.NewEncoder(w).Encode(monitor)
		default:
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	profiles := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(profiles, 0700))
	for _, sandbox := range []containerView{work, other} {
		owned := "# tinfoil-resource: " + os.Getenv(envCPURL) + "//owner/" + sandbox.ID + "\n"
		require.NoError(t, os.WriteFile(filepath.Join(profiles, sandbox.Name+".conf"), []byte(owned), 0600))
	}
	var stderr strings.Builder
	previousStderr := rootCmd.ErrOrStderr()
	rootCmd.SetErr(&stderr)
	t.Cleanup(func() { rootCmd.SetErr(previousStderr) })
	run := func(args ...string) error {
		stderr.Reset()
		_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, args...) })
		return err
	}

	require.NoError(t, run("monitor", "stop", "mon"))
	require.Contains(t, stderr.String(), "Stopping Monitor mon and its sandboxes work.")
	require.NoError(t, run("monitor", "delete", "mon", "--yes"))
	require.Contains(t, stderr.String(), "Deleting Monitor mon and its sandboxes work.")
	require.Equal(t, []string{"POST /api/monitors/" + monitor.ID + "/stop", "DELETE /api/monitors/" + monitor.ID}, mutations)
	require.NoFileExists(t, filepath.Join(profiles, "work.conf"))
	require.FileExists(t, filepath.Join(profiles, "other.conf"))

	mutations = nil
	for _, verb := range []string{"stop", "delete"} {
		require.ErrorContains(t, run("container", verb, "mon"), "`tinfoil monitor "+verb+" mon`")
	}
	monitor.ClerkUserID = "member"
	require.ErrorContains(t, run("monitor", "stop", "mon"), "created by another user")
	require.ErrorContains(t, run("monitor", "delete", "mon", "--yes"), "created by another user")
	require.Empty(t, mutations)
}

func TestManagedUpdatesUseContainerPlan(t *testing.T) {
	for _, kind := range []string{"sandbox", "monitor"} {
		calls := []string{}
		managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				calls = append(calls, r.URL.Path)
				var body map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.Equal(t, false, body["hold"])
				require.Equal(t, "v2", body["tag"])
				if strings.HasSuffix(r.URL.Path, "/plan") {
					w.Write([]byte(updatePlanFixture))
					return
				}
			}
			json.NewEncoder(w).Encode(containerView{ID: testContainerID, Repo: managedRepo(kind), Status: statusRunning})
		})
		_, err := captureTestStdout(func() error {
			return executeLifecycleCLI(t, kind, "update", testContainerID, "--tag", "v2", "--yes", "--no-wait")
		})
		require.NoError(t, err)
		path := "/api/containers/" + testContainerID + "/update"
		require.Equal(t, []string{path + "/plan", path + "/plan", path}, calls)
	}
}

func TestManagedStatusFiltersAndWatches(t *testing.T) {
	row := containerView{ID: testContainerID, Repo: monitorRepo, Name: "personal"}
	reads := 0
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/containers" {
			json.NewEncoder(w).Encode([]containerView{row, {Repo: monitorRepo, Debug: true}, {Repo: defaultSandboxRepo}})
		} else {
			reads++
			if reads == 4 {
				cancel()
			}
			row.Status = []string{statusCreated, statusDeploying, statusRunning}[min(reads-1, 2)]
			json.NewEncoder(w).Encode(row)
		}
	})
	for _, verb := range []string{"status", "get", "list", "ls"} {
		out, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "monitor", verb) })
		require.NoError(t, err)
		var rows []containerView
		require.NoError(t, json.Unmarshal(out, &rows))
		require.Len(t, rows, 1)
	}
	previous := followInterval
	followInterval = time.Millisecond
	t.Cleanup(func() { followInterval = previous })
	outputFormat = "table"
	cmd := newManagedStatusCmd("monitor")
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Flags().Set("watch", "true"))
	out, err := captureTestStdout(func() error { return cmd.RunE(cmd, []string{row.ID}) })
	require.NoError(t, err)
	for _, status := range []string{"Created", "Deploying", "Running"} {
		require.Contains(t, string(out), status)
	}
}

func TestSandboxStatusShowsWorkspaceSize(t *testing.T) {
	const volumeID = "22222222-2222-4222-8222-222222222222"
	row := containerView{ID: testContainerID, Name: "work", Repo: defaultSandboxRepo, Status: statusRunning,
		VolumeSlots: []volumeSlot{{Name: "workspace"}}, Volumes: map[string]string{"workspace": volumeID}}
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/containers/" + testContainerID:
			json.NewEncoder(w).Encode(row)
		case "GET /api/volumes":
			json.NewEncoder(w).Encode(volumeList{Volumes: []volumeView{{ID: volumeID, Name: "work-ws", SizeBytes: 32e9, Sandbox: true}}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	outputFormat = "table"
	cmd := newManagedStatusCmd("sandbox")
	out, err := captureTestStdout(func() error { return cmd.RunE(cmd, []string{testContainerID}) })
	require.NoError(t, err)
	require.Contains(t, string(out), "Volumes:      workspace ← work-ws (32 GB)\n")
}

func TestSandboxCreationOnlySelectsOwnMonitors(t *testing.T) {
	own := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "mine", Repo: monitorRepo, ClerkUserID: "user_test"}
	other := containerView{ID: "33333333-3333-4333-8333-333333333333", Name: "shared", Repo: monitorRepo, ClerkUserID: "user_other", Status: statusRunning}
	second := containerView{ID: "44444444-4444-4444-8444-444444444444", Name: "spare", Repo: monitorRepo, ClerkUserID: "user_second"}
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		switch r.URL.Path {
		case "/api/containers":
			json.NewEncoder(w).Encode([]containerView{other, own, second, {Name: "spare-copy", Repo: monitorRepo, ClerkUserID: "user_second"}})
		case "/api/containers/" + own.ID:
			json.NewEncoder(w).Encode(own)
		case "/api/containers/" + other.ID:
			json.NewEncoder(w).Encode(other)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	client, err := authedClient()
	require.NoError(t, err)
	selected, err := selectCreationMonitor(client, "", "user_test")
	require.NoError(t, err)
	require.Equal(t, own.ID, selected.ID, "another member's Monitor must not count toward the default")
	_, err = selectCreationMonitor(client, other.ID, "user_test")
	require.ErrorContains(t, err, "Monitor shared was created by another user")
	_, err = selectCreationMonitor(client, "", "user_without_monitor")
	require.ErrorContains(t, err, "you have no Monitors in this account; create one")
	_, err = selectCreationMonitor(client, "", "user_second")
	require.EqualError(t, err, "choose one of your Monitors with --monitor: spare, spare-copy")
}

// testUserKey writes a fresh Ed25519 public key file for UMK creation.
func testUserKey(t *testing.T) (string, string) {
	t.Helper()
	owner := ed25519PublicKeyString(testSeed(t))
	key, err := measuredOwner(owner)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "owner.pub")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0600))
	return owner, path
}

func TestManagedCreateUsesContainerRecovery(t *testing.T) {
	previousIdentity, previousInterval := attestSSHIdentity, followInterval
	attestSSHIdentity, followInterval = "", 0
	t.Cleanup(func() { attestSSHIdentity, followInterval = previousIdentity, previousInterval })
	for _, kind := range []string{"monitor", "sandbox"} {
		for _, state := range []string{"follow", "no-wait", "json", "uncertain", "attached"} {
			if kind == "monitor" && state == "attached" {
				continue
			}
			t.Run(kind+"/"+state, func(t *testing.T) {
				owner, publicFile := testUserKey(t)
				posts, polls := 0, 0
				keys := &keyStateServer{}
				volume := volumeView{ID: "22222222-2222-4222-8222-222222222222", Sandbox: true}
				if state == "attached" {
					volume.ContainerID = "another-sandbox"
				}
				managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
					switch r.Method + " " + r.URL.Path {
					case "GET /api/auth/context":
						w.Write([]byte(`{"context_type":"personal","organization":null,"user_id":"user_test"}`))
					case "GET " + keyStatePath, "PUT " + keyStatePath:
						keys.ServeHTTP(w, r)
					case "GET /api/containers/11111111-1111-4111-8111-111111111111":
						json.NewEncoder(w).Encode(containerView{ID: "11111111-1111-4111-8111-111111111111", Repo: monitorRepo, ClerkUserID: "user_test", OwnerKeyMode: "umk"})
					case "GET /api/volumes":
						json.NewEncoder(w).Encode(volumeList{Volumes: []volumeView{volume}})
					case "POST /api/containers":
						posts++
						var body map[string]json.RawMessage
						require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
						require.JSONEq(t, `"umk"`, string(body["owner_key_mode"]))
						require.JSONEq(t, fmt.Sprintf("%q", owner), string(body["owner_public_key"]))
						var variables map[string]string
						require.NoError(t, json.Unmarshal(body["variables"], &variables))
						require.NotContains(t, variables, monitorOwnerEnv, "controlplane renders the measured owner key")
						require.NotContains(t, variables, sandboxOwnerEnv, "controlplane renders the measured owner key")
						if kind == "sandbox" {
							require.True(t, looksLikeUUID(variables["SANDBOX_INSTANCE_ID"]))
							var policy containerNetworkPolicy
							require.NoError(t, json.Unmarshal(body["network_policy"], &policy))
							require.Equal(t, sandboxNetworkPolicy("11111111-1111-4111-8111-111111111111"), policy)
							require.JSONEq(t, `{"workspace":"22222222-2222-4222-8222-222222222222"}`, string(body["volumes"]))
						} else {
							require.JSONEq(t, `{}`, string(body["object_storage"]))
						}
						if state == "uncertain" {
							http.Error(w, "upstream disconnected", 502)
							return
						}
						json.NewEncoder(w).Encode(containerView{ID: testContainerID, Name: "work", Status: statusDeploying, TinfoildDeploymentID: "deployment"})
					case "GET /api/containers/" + testContainerID:
						polls++
						json.NewEncoder(w).Encode(containerView{ID: testContainerID, Name: "work", Status: statusRunning, TinfoildDeploymentID: "deployment"})
					default:
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
					}
				})
				outputFormat = "table"
				if state == "json" {
					outputFormat = "json"
				}
				cmd := newManagedCreateCmd(kind)
				cmd.SetContext(t.Context())
				args := []string{"--tag", "v1", "work", "--owner-public-key", publicFile}
				if state == "no-wait" {
					args = append(args, "--no-wait")
				}
				if kind == "sandbox" {
					args = append(args, "--monitor", "11111111-1111-4111-8111-111111111111", "--workspace", "22222222-2222-4222-8222-222222222222")
				}
				require.NoError(t, cmd.ParseFlags(args))
				_, err := captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
				switch state {
				case "attached":
					require.ErrorContains(t, err, "already attached")
					require.Zero(t, posts, "attached workspaces must be rejected before creation")
					return
				case "uncertain":
					require.ErrorContains(t, err, "inspect `tinfoil "+kind+" status` before retrying")
				default:
					require.NoError(t, err)
				}
				require.Equal(t, 1, posts)
				require.Equal(t, state == "follow", polls == 1)
			})
		}
	}
	_, publicFile := testUserKey(t)
	raw, err := os.ReadFile(publicFile)
	require.NoError(t, err)
	public := string(raw)
	for _, invalid := range []string{public + public, "restrict " + public, "-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-ed25519 YQ=="} {
		require.NoError(t, os.WriteFile(publicFile, []byte(invalid), 0600))
		_, err := creationOwnerKey(publicFile, "")
		require.Error(t, err, strings.TrimSpace(invalid))
	}
}

func TestSyncedCreateSavesKeysBeforeAllocation(t *testing.T) {
	keys := &keyStateServer{}
	var dek []byte
	monitor := containerView{ID: "11111111-1111-4111-8111-111111111111", Repo: monitorRepo, ClerkUserID: "user_owner", OwnerKeyMode: "umk"}
	var created []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			w.Write([]byte(`{"context_type":"personal","organization":null,"user_id":"user_owner"}`))
		case "GET " + keyStatePath, "PUT " + keyStatePath:
			keys.ServeHTTP(w, r)
		case "GET /api/containers/" + monitor.ID:
			json.NewEncoder(w).Encode(monitor)
		case "POST /api/containers":
			var body struct {
				Mode  string `json:"owner_key_mode"`
				Owner string `json:"owner_public_key"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "tmk", body.Mode)
			payload := keys.payload(t, dek, mkContext{APIOrigin: fixedAPIOrigin, UserID: "user_owner", DEKID: *keys.dekID})
			saved := findKey(payload, func(k *mkResource) bool { return k.OwnerPublicKey == body.Owner })
			require.NotNil(t, saved, "the key bundle holds the owner key before allocation")
			require.Nil(t, saved.Binding)
			created = append(created, saved.Kind)
			json.NewEncoder(w).Encode(containerView{ID: testContainerID, Name: "work", Status: statusDeploying})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	_, _, dek = testLogin(t, server, keys)
	outputFormat = "table"
	cmd := newManagedCreateCmd("monitor")
	cmd.SetContext(t.Context())
	require.NoError(t, cmd.ParseFlags([]string{"--tag", "v1", "--no-wait", "work"}))
	_, err := captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
	require.NoError(t, err)
	require.Equal(t, []string{"monitor"}, created)

	cmd = newManagedCreateCmd("sandbox")
	cmd.SetContext(t.Context())
	require.NoError(t, cmd.ParseFlags([]string{"--tag", "v1", "--no-wait", "--monitor", monitor.ID, "work"}))
	_, err = captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
	require.ErrorContains(t, err, "uses your own keys", "a UMK Monitor cannot serve a synced sandbox")
	monitor.OwnerKeyMode = "tmk"
	_, err = captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
	require.NoError(t, err)
	require.Equal(t, []string{"monitor", "sandbox"}, created)
}

func TestSandboxCreateWorkspaceSize(t *testing.T) {
	const monitorID = "11111111-1111-4111-8111-111111111111"
	previousIdentity := attestSSHIdentity
	attestSSHIdentity = ""
	t.Cleanup(func() { attestSSHIdentity = previousIdentity })
	for _, tt := range []struct {
		name     string
		args     []string
		limitHit bool
		wantSize json.RawMessage
		wantErr  string
	}{
		{name: "omitted lets the server choose"},
		{name: "chosen size is sent", args: []string{"--workspace-size", "32"}, wantSize: json.RawMessage("32")},
		{name: "size outside the allowed list", args: []string{"--workspace-size", "16000"}, wantErr: "--workspace-size must be 2, 4, 8, 16, 32, or 64 (GB)"},
		{name: "reused workspace keeps its size", args: []string{"--workspace-size", "8", "--workspace", "old"}, wantErr: "--workspace-size cannot be combined with --workspace"},
		{name: "storage limit", args: []string{"--workspace-size", "64"}, limitHit: true, wantSize: json.RawMessage("64"), wantErr: "only 8 GB of your 32 GB storage limit (Tier 1) is free"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var sent map[string]json.RawMessage
			keys := &keyStateServer{}
			_, publicFile := testUserKey(t)
			managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /api/auth/context":
					w.Write([]byte(`{"context_type":"personal","organization":null,"user_id":"user_test"}`))
				case "GET " + keyStatePath, "PUT " + keyStatePath:
					keys.ServeHTTP(w, r)
				case "GET /api/containers/" + monitorID:
					json.NewEncoder(w).Encode(containerView{ID: monitorID, Repo: monitorRepo, ClerkUserID: "user_test", OwnerKeyMode: "umk"})
				case "POST /api/containers":
					require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
					if tt.limitHit {
						w.WriteHeader(http.StatusConflict)
						w.Write([]byte(`{"error":"Your new sandbox needs a 64 GB workspace, but only 8 GB of your 32 GB storage limit (Tier 1) is free.","code":"STORAGE_LIMIT_EXCEEDED"}`))
						return
					}
					json.NewEncoder(w).Encode(containerView{ID: testContainerID, Name: "work", Status: statusDeploying})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			})
			outputFormat = "table"
			cmd := newManagedCreateCmd("sandbox")
			cmd.SetContext(t.Context())
			require.NoError(t, cmd.ParseFlags(append([]string{"--tag", "v1", "--monitor", monitorID, "--no-wait", "--owner-public-key", publicFile, "work"}, tt.args...)))
			_, err := captureTestStdout(func() error { return cmd.RunE(cmd, cmd.Flags().Args()) })
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.limitHit {
				require.Equal(t, accountLimitsHint, errorHint(err))
			}
			if tt.wantErr != "" && !tt.limitHit {
				require.Nil(t, sent, "invalid flags must be rejected before creation")
				return
			}
			require.Equal(t, tt.wantSize, sent["workspace_size_gb"])
		})
	}
}

func TestSandboxWorkspaceIgnoresContainerVolumes(t *testing.T) {
	workspace := volumeView{ID: "22222222-2222-4222-8222-222222222222", Name: "data", Sandbox: true}
	managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET /api/volumes", r.Method+" "+r.URL.Path)
		json.NewEncoder(w).Encode(volumeList{Volumes: []volumeView{
			workspace,
			{ID: "33333333-3333-4333-8333-333333333333", Name: "data"},
			{ID: "44444444-4444-4444-8444-444444444444", Name: "logs"},
		}})
	})
	client, err := authedClient()
	require.NoError(t, err)
	volume, err := lookupSandboxWorkspace(client, "data")
	require.NoError(t, err, "a container volume with the same name must not make the workspace ambiguous")
	require.Equal(t, workspace.ID, volume.ID)
	for _, identifier := range []string{"logs", "44444444-4444-4444-8444-444444444444"} {
		_, err = lookupSandboxWorkspace(client, identifier)
		require.ErrorContains(t, err, "volume logs is a container volume")
	}
	_, err = lookupSandboxWorkspace(client, "missing")
	require.ErrorContains(t, err, `no volume named "missing"`)
}

func TestContainerVolumesIgnoreSandboxWorkspaces(t *testing.T) {
	volumes := []volumeView{
		{ID: "11111111-1111-4111-8111-111111111111", Name: "data", Sandbox: true},
		{ID: "22222222-2222-4222-8222-222222222222", Name: "data"},
		{ID: "33333333-3333-4333-8333-333333333333", Name: "workspace", Sandbox: true},
	}
	resolved, err := resolveVolumeRequests(volumes, []volumeRequest{{identifier: "data"}}, nil)
	require.NoError(t, err, "a sandbox workspace with the same name must not make the container volume ambiguous")
	require.Equal(t, volumes[1].ID, resolved[0].ID)
	_, err = resolveVolumeRequests(volumes, []volumeRequest{{identifier: "workspace"}}, nil)
	require.ErrorContains(t, err, "volume workspace is a sandbox volume")

	for _, sandbox := range []bool{false, true} {
		target := containerView{ID: testContainerID, Name: "work", Status: statusStopped, VolumeSlots: []volumeSlot{{Name: "workspace"}}}
		want := volumes[1].ID
		if sandbox {
			target.Repo, want = defaultSandboxRepo, volumes[0].ID
		}
		var attached string
		managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.Path {
			case "GET /api/containers/" + testContainerID:
				json.NewEncoder(w).Encode(target)
			case "GET /api/volumes":
				json.NewEncoder(w).Encode(volumeList{Volumes: volumes})
			case "PUT /api/containers/" + testContainerID + "/volumes/workspace":
				var body map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				attached = body["volume_id"]
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
			}
		})
		_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "volume", "attach", "data", testContainerID) })
		require.NoError(t, err)
		require.Equal(t, want, attached, "volume attach resolves the volume kind that matches the target")
	}
}
