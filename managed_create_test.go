package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const managedTestMonitorID = "11111111-1111-4111-8111-111111111111"
const managedTestWorkspaceID = "22222222-2222-4222-8222-222222222222"

func managedTestIntent(t *testing.T, kind string) (pendingCreation, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p := pendingCreation{Version: 1, Scope: accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}, Kind: kind, Name: "work", Tag: "v1.2.3", Owner: "ed25519:" + base64.StdEncoding.EncodeToString(public), Instance: "33333333-3333-4333-8333-333333333333"}
	if kind == "sandbox" {
		p.Monitor = &monitorBinding{ContainerID: managedTestMonitorID, Owner: p.Owner}
	}
	path := filepath.Join(t.TempDir(), "pending.json")
	require.NoError(t, writeStorageJSON(path, p, true))
	return p, path
}

func managedTestRow(t *testing.T, p pendingCreation) containerView {
	t.Helper()
	row := containerView{ID: testContainerID, Name: p.Name, Repo: managedRepo(p.Kind), CurrentTag: p.Tag, Status: statusRunning}
	row.Config = fmt.Sprintf("containers:\n  - env:\n      - %s: %q\n", managedOwnerEnv(p.Kind), p.Owner)
	if p.Kind == "sandbox" {
		binding, err := json.Marshal(p.Monitor)
		require.NoError(t, err)
		row.Config += fmt.Sprintf("      - SANDBOX_INSTANCE_ID: %q\n      - MONITOR_BINDING: %q\n", p.Instance, string(binding))
		row.NetworkPolicy = &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: p.Monitor.ContainerID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}
		workspace := p.Workspace
		if workspace == "" {
			workspace = managedTestWorkspaceID
		}
		row.Volumes = map[string]string{"workspace": workspace}
	}
	row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
	return row
}

func managedTestResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}
}

func TestManagedCreationRecoversLostReplyWithoutDuplicatePOST(t *testing.T) {
	for _, kind := range []string{"monitor", "sandbox", "sandbox-reuse"} {
		t.Run(kind, func(t *testing.T) {
			p, path := managedTestIntent(t, strings.Split(kind, "-")[0])
			if kind == "sandbox-reuse" {
				p.Workspace = managedTestWorkspaceID
				require.NoError(t, writeStorageJSON(path, p, false))
			}
			row := managedTestRow(t, p)
			posts, visible := 0, false
			client := newCPClient(cliConfig{ControlplaneURL: p.Scope.ControlplaneURL, APIKey: "admin_secret"})
			client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				switch r.Method + " " + r.URL.Path {
				case "GET /api/containers":
					if visible {
						return managedTestResponse(t, []containerView{row}), nil
					}
					return managedTestResponse(t, []containerView{}), nil
				case "GET /api/volumes":
					return managedTestResponse(t, volumeList{CanCreateVolumes: kind != "sandbox-reuse", BillingExempt: true, AvailableBytes: sandboxWorkspaceBytes, Volumes: []volumeView{{ID: managedTestWorkspaceID, Name: "saved", SizeBytes: sandboxWorkspaceBytes, HostID: "disk-host"}}}), nil
				case "POST /api/containers":
					posts++
					var body map[string]json.RawMessage
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					saved, err := readPendingCreation(path, p.Scope)
					require.NoError(t, err)
					require.True(t, saved.Submitted, "must persist submission before crossing the request boundary")
					require.Equal(t, p.Instance, saved.Instance)
					require.NotContains(t, string(body["variables"]), "PRIVATE")
					if kind == "monitor" {
						require.JSONEq(t, `{}`, string(body["object_storage"]))
						require.NotContains(t, body, "volumes")
					} else {
						var policy containerNetworkPolicy
						require.NoError(t, json.Unmarshal(body["network_policy"], &policy))
						require.Equal(t, row.NetworkPolicy, &policy)
						require.NotContains(t, body, "host_id", "reuse must let the server use the disk's existing host")
						var variables map[string]string
						require.NoError(t, json.Unmarshal(body["variables"], &variables))
						require.Equal(t, p.Instance, variables["SANDBOX_INSTANCE_ID"])
						if p.Workspace != "" {
							require.JSONEq(t, `{"workspace":"`+p.Workspace+`"}`, string(body["volumes"]))
						}
					}
					return nil, errors.New("connection lost after the server accepted creation")
				case "GET /api/containers/" + row.ID:
					return managedTestResponse(t, row), nil
				default:
					t.Fatalf("unexpected request, including any extra deploy: %s %s", r.Method, r.URL.Path)
					return nil, errors.New("unexpected request")
				}
			})
			_, _, err := provisionManaged(context.Background(), client, path, &p, false, io.Discard)
			require.ErrorContains(t, err, "connection lost")
			p, err = readPendingCreation(path, p.Scope)
			require.NoError(t, err)
			_, _, err = provisionManaged(context.Background(), client, path, &p, false, io.Discard)
			require.ErrorContains(t, err, "no duplicate request was sent")
			visible = true
			got, complete, err := provisionManaged(context.Background(), client, path, &p, false, io.Discard)
			require.NoError(t, err)
			require.True(t, complete)
			require.Equal(t, row.ID, got.ID)
			require.Equal(t, 1, posts)
			saved, err := readPendingCreation(path, p.Scope)
			require.NoError(t, err)
			require.Equal(t, row.ID, saved.ID)
		})
	}
}

func TestManagedResumeRejectsChangedMeasuredBindingsAndWorkspace(t *testing.T) {
	for _, change := range []string{"owner", "instance", "monitor", "tag", "name", "id", "debug", "repo", "workspace", "network", "during-boot"} {
		t.Run(change, func(t *testing.T) {
			p, path := managedTestIntent(t, "sandbox")
			p.Workspace, p.ID, p.Submitted = managedTestWorkspaceID, testContainerID, true
			require.NoError(t, writeStorageJSON(path, p, false))
			row := managedTestRow(t, p)
			switch change {
			case "owner":
				row.Config = strings.ReplaceAll(row.Config, p.Owner, "ed25519:wrong")
			case "instance":
				row.Config = strings.ReplaceAll(row.Config, p.Instance, managedTestWorkspaceID)
			case "monitor":
				row.Config = strings.ReplaceAll(row.Config, p.Monitor.ContainerID, managedTestWorkspaceID)
			case "tag":
				row.CurrentTag = "v9"
			case "name":
				row.Name = "replacement"
			case "id":
				row.ID = managedTestMonitorID
			case "debug":
				row.Debug = true
			case "repo":
				row.Repo = monitorRepo
			case "workspace":
				row.Volumes["workspace"] = managedTestMonitorID
			case "network":
				row.NetworkPolicy.Public = true
			}
			reads := 0
			client := newCPClient(cliConfig{ControlplaneURL: p.Scope.ControlplaneURL})
			client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "GET", r.Method)
				reads++
				if change == "during-boot" && reads > 1 {
					row.CurrentTag = "v9"
				}
				return managedTestResponse(t, row), nil
			})
			_, complete, err := provisionManaged(context.Background(), client, path, &p, false, io.Discard)
			require.Error(t, err)
			require.False(t, complete)
			require.FileExists(t, path)
		})
	}
}

func TestWorkspacePreflightFailsClosedButAllowsReuseWithoutQuota(t *testing.T) {
	rate := 0.0002
	for _, tc := range []struct {
		name string
		id   string
		list volumeList
		want string
	}{
		{"missing capability", "", volumeList{AvailableBytes: sandboxWorkspaceBytes, StorageGiBPerHour: &rate}, "pricing unavailable"},
		{"missing price", "", volumeList{CanCreateVolumes: true, AvailableBytes: sandboxWorkspaceBytes}, "pricing unavailable"},
		{"capacity", "", volumeList{CanCreateVolumes: true, BillingExempt: true}, "pricing unavailable"},
		{"new workspace", "", volumeList{CanCreateVolumes: true, AvailableBytes: sandboxWorkspaceBytes, StorageGiBPerHour: &rate}, ""},
		{"exempt", "", volumeList{CanCreateVolumes: true, AvailableBytes: sandboxWorkspaceBytes, BillingExempt: true}, ""},
		{"reuse no quota", managedTestWorkspaceID, volumeList{Volumes: []volumeView{{ID: managedTestWorkspaceID, SizeBytes: sandboxWorkspaceBytes}}}, ""},
		{"attached", managedTestWorkspaceID, volumeList{Volumes: []volumeView{{ID: managedTestWorkspaceID, SizeBytes: sandboxWorkspaceBytes, ContainerID: testContainerID}}}, "attached"},
		{"deleted", managedTestWorkspaceID, volumeList{Volumes: []volumeView{{ID: managedTestWorkspaceID, SizeBytes: sandboxWorkspaceBytes, BillingEndedAt: "yesterday"}}}, "deleted"},
		{"too small", managedTestWorkspaceID, volumeList{Volumes: []volumeView{{ID: managedTestWorkspaceID, SizeBytes: 1}}}, "too small"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newCPClient(cliConfig{ControlplaneURL: "https://cp.example"})
			client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "GET", r.Method)
				return managedTestResponse(t, tc.list), nil
			})
			err := checkCreationWorkspace(context.Background(), client, tc.id, io.Discard)
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
		})
	}
}

func TestPendingCreationAccountScopeCorruptionAndLock(t *testing.T) {
	p, path := managedTestIntent(t, "monitor")
	other := p.Scope
	other.OrgID = "other-account"
	_, err := readPendingCreation(path, other)
	require.ErrorContains(t, err, "account scope")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	a, err := pendingCreationPath(p.Scope)
	require.NoError(t, err)
	b, err := pendingCreationPath(other)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	unlock, err := acquireStorageLock(path)
	require.NoError(t, err)
	_, err = acquireStorageLock(path)
	require.ErrorContains(t, err, "locked")
	unlock()
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err = readPendingCreation(path, p.Scope)
	require.ErrorContains(t, err, "check resource lists")
}

func TestCreationOwnerAcceptsOnlyOnePublicEd25519Key(t *testing.T) {
	p, _ := managedTestIntent(t, "monitor")
	key, err := measuredOwner(p.Owner)
	require.NoError(t, err)
	public := string(ssh.MarshalAuthorizedKey(key))
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"public", public, true}, {"comment", strings.TrimSpace(public) + " owner@example\n", true},
		{"two keys", public + public, false}, {"private", "-----BEGIN OPENSSH PRIVATE KEY-----", false},
		{"options", "restrict " + public, false}, {"invalid", "ssh-ed25519 YQ==", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "owner.pub")
			require.NoError(t, os.WriteFile(path, []byte(tc.input), 0600))
			owner, err := creationOwnerKey(path, "", "")
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, p.Owner, owner)
			} else {
				require.Error(t, err)
			}
		})
	}
}
