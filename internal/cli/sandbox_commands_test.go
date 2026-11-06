package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSandboxStartUsesSavedAliasWithoutMonitorLookup(t *testing.T) {
	commandState := newCommandFixture()

	previous := commandState.pollingOpts.followInterval
	commandState.pollingOpts.followInterval = 0
	t.Cleanup(func() { commandState.pollingOpts.followInterval = previous })
	for _, tc := range []struct {
		state   string
		restart bool
	}{
		{statusStopped, false}, {statusFailed, false}, {statusStopped, true}, {statusFailed, true}, {statusRunning, true}, {statusStopping, true},
	} {
		t.Run(fmt.Sprintf("%s/restart=%t", tc.state, tc.restart), func(t *testing.T) {
			const monitorID = "11111111-1111-4111-8111-111111111111"
			row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Status: tc.state, UpdateStatus: statusFailed,
				ConfigName: "/tinfoil/containers/saved-digest", Config: "containers: [{env: []}]",
				NetworkPolicy: &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}}
			var mutations []string
			client := testCPClient(cliConfig{ControlplaneURL: "https://cp.example"})
			client.http.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				require.Nil(t, r.Body, "start and restart must not send boot variables")
				if r.Method == "POST" {
					mutations = append(mutations, r.URL.Path)
				}
				switch r.Method + " " + r.URL.Path {
				case "GET /api/containers/work-id":
					row.Status = statusStopped
				case "POST /api/containers/work-id/stop":
					row.Status = statusStopping
				case "POST /api/containers/work-id/deploy":
					// Stop before enrollment while checking that boot errors propagate.
					row.Status, row.ErrorMessage, row.UpdateStatus = statusFailed, "test boot failure", ""
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
				}
				body, err := json.Marshal(row)
				require.NoError(t, err)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})
			_, err := startSandboxRow(commandState.pollingOpts, testStreams(), client, row, tc.restart)
			require.ErrorContains(t, err, "test boot failure")
			expected := []string{"/api/containers/work-id/deploy"}
			if tc.restart && tc.state == statusRunning {
				expected = append([]string{"/api/containers/work-id/stop"}, expected...)
			}
			require.Equal(t, expected, mutations)
		})
	}
}

func TestSandboxRequiresRestrictedAliasBeforeStoppingOrDeploying(t *testing.T) {
	commandState := newCommandFixture()

	const monitorID = "11111111-1111-4111-8111-111111111111"
	row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Config: "containers: [{env: []}]"}
	peer := containerPeer{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid policy made a request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := testCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "test"})
	for _, policy := range []*containerNetworkPolicy{nil, {}, {Public: true}, {EgressMode: "unrestricted"},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22}}},
		{Public: true, EgressMode: "restricted", Egress: []containerPeer{peer}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 443, Alias: peer.Alias}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: "other", Port: 22, Alias: peer.Alias}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "100.127.255.253", Port: 22}}}},
		{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 23}}}},
		{EgressMode: "restricted", Egress: []containerPeer{peer, peer}}} {
		row.NetworkPolicy = policy
		for _, state := range []string{statusRunning, statusStopped} {
			row.Status = state
			_, err := startSandboxRow(commandState.pollingOpts, testStreams(), client, row, state == statusRunning)
			require.ErrorContains(t, err, "TCP alias")
		}
	}
	row.NetworkPolicy = &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{peer}}
	require.NoError(t, validateSandboxNetwork(row))
}

func TestSandboxDeleteKeepsCredentialsAndRemovesOwnedProfile(t *testing.T) {
	commandState := newCommandFixture()
	owner := ed25519PublicKeyString(testSeed(t))
	const workspaceID = "22222222-2222-4222-8222-222222222222"
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo, Status: statusRunning, OwnerKeyMode: "umk", OwnerPublicKey: owner, Volumes: map[string]string{sandboxWorkspaceSlot: workspaceID}}
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers":
			if deleted {
				json.NewEncoder(w).Encode([]containerView{})
			} else {
				json.NewEncoder(w).Encode([]containerView{row})
			}
		case "GET /api/containers/" + row.ID:
			if deleted {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(row)
		case "DELETE /api/containers/" + row.ID:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	commandState.sandboxActionOpts.sandboxYes = true
	profile := filepath.Join(home, ".ssh", "tinfoil", "work.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(profile), 0700))
	require.NoError(t, os.WriteFile(profile, []byte("# tinfoil-resource: "+server.URL+"//owner/"+row.ID+"\n"), 0600))
	credential, err := umkRecordPath(accountScope{ControlplaneURL: server.URL, UserID: "owner"}, row.ID)
	require.NoError(t, err)
	_, err = saveUMKRecord(credential, newUMKRecord("sandbox", owner))
	require.NoError(t, err)
	before, err := os.ReadFile(credential)
	require.NoError(t, err)
	var warning strings.Builder
	commandState.sandboxDeleteCmd.SetErr(&warning)
	for _, identifier := range []string{row.Name, row.ID} {
		require.NoError(t, commandState.sandboxDeleteCmd.RunE(commandState.sandboxDeleteCmd, []string{identifier}))
	}
	require.Contains(t, warning.String(), "permanently deletes its workspace volume")
	require.Contains(t, warning.String(), "`tinfoil volume detach "+workspaceID+"`")
	after, err := os.ReadFile(credential)
	require.NoError(t, err)
	require.Equal(t, before, after, "deletion must preserve encryption and owner signing keys")
	require.NoFileExists(t, profile)
}

func TestContainedProfileJumpsThroughMonitorAndKeepsItsAlias(t *testing.T) {
	program, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client unavailable")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	boot, monitorKey := testHostKey(t), testHostKey(t)
	profile := sshProfile{resourceID: "cp/org/user/resource", name: "work", hostName: routeName(boot), port: defaultSSHPort, user: sandboxLoginUser, identityFile: "/keys/my work/owner_ed25519", hostKey: boot, hostKeyAlias: "work.acme.sandboxes.tinfoil.dev", jump: monitorJump("work", "203.0.113.8", 22042, "/keys/personal", monitorKey, "personal.acme.monitors.tinfoil.dev")}
	other := []byte("Host work\n  HostName work.example\n  IdentityFile ~/.ssh/id_work\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), other, 0o600))
	require.ErrorContains(t, installSandboxAlias(testStreams(), profile, home), "profile of another resource")
	kept, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Equal(t, other, kept, "another host keeps its alias")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), []byte("# tinfoil-resource: cp/org/user/resource\nHost work\n"), 0600))
	require.NoError(t, installSandboxAlias(testStreams(), profile, home))
	updated, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Contains(t, string(updated), "IdentityFile \"/keys/my work/owner_ed25519\"\n")
	rebooted := testHostKey(t)
	profile.hostName, profile.hostKey = routeName(rebooted), rebooted
	require.NoError(t, installSandboxAlias(testStreams(), profile, home), "a new boot replaces this sandbox's own profile")
	path := filepath.Join(dir, "work.conf")
	for host, expected := range map[string][]string{
		"work":         {"hostname " + strings.ToLower(routeName(rebooted)), "proxyjump work.monitor", "hostkeyalias work.acme.sandboxes.tinfoil.dev", "user sandbox", "stricthostkeychecking true"},
		"work.monitor": {"hostname 203.0.113.8", "port 22042", "hostkeyalias personal.acme.monitors.tinfoil.dev", "identityfile /keys/personal/device_ed25519", "identityagent none"},
	} {
		data, err := exec.Command(program, "-G", "-F", path, host).Output()
		require.NoError(t, err)
		for _, want := range expected {
			require.Contains(t, string(data), want+"\n", host)
		}
	}
	data, err := exec.Command(program, "-G", "-F", path, "work").Output()
	require.NoError(t, err)
	require.NotContains(t, string(data), "identityagent none\n", "the sandbox hop may still use an agent-held owner key")
	pins, err := knownhosts.New(filepath.Join(dir, "work.known_hosts"))
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: defaultSSHPort}
	require.NoError(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, rebooted))
	require.NoError(t, pins("personal.acme.monitors.tinfoil.dev:22", remote, monitorKey))
	require.Error(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, boot), "the previous boot is no longer trusted")
	require.Error(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, monitorKey), "Monitor cannot impersonate the sandbox")
}

func TestRepinSandboxKeepsAliasesAndOtherResources(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	const resource = "https://cp.example//user_owner/resource"
	alias := filepath.Join(dir, "saved-alias.conf")
	require.NoError(t, os.WriteFile(alias, []byte("# tinfoil-resource: "+resource+"\nHost saved-alias\n"), 0o600))
	const other = "# tinfoil-resource: another/resource\nHost other\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.conf"), []byte(other), 0o600))
	host, monitor := testHostKey(t), testHostKey(t)
	session := &sandboxSession{profile: sshProfile{resourceID: resource, name: "renamed-work", hostName: routeName(host), port: defaultSSHPort, user: sandboxLoginUser,
		identityFile: filepath.Join(home, "owner"), hostKey: host, hostKeyAlias: "work.example", jump: monitorJump("renamed-work", "monitor.example", defaultSSHPort, home, monitor, "monitor.example")}}
	require.NoError(t, session.repinInstalled(testStreams()))
	config, err := os.ReadFile(alias)
	require.NoError(t, err)
	require.Contains(t, string(config), "Host saved-alias\n")
	require.Contains(t, string(config), "ProxyJump saved-alias.monitor\n")
	pins, err := knownhosts.New(filepath.Join(dir, "saved-alias.known_hosts"))
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: defaultSSHPort}
	require.NoError(t, pins("work.example:22", remote, host))
	require.NoError(t, pins("monitor.example:22", remote, monitor))
	retained, err := os.ReadFile(filepath.Join(dir, "other.conf"))
	require.NoError(t, err)
	require.Equal(t, other, string(retained))
	require.NoFileExists(t, filepath.Join(dir, "other.known_hosts"))
	require.NoFileExists(t, filepath.Join(dir, "renamed-work.conf"), "re-linking only updates installed aliases")
}
