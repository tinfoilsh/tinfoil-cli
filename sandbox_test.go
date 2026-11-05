package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSandboxStartUsesSavedAliasWithoutMonitorLookup(t *testing.T) {
	previous := followInterval
	followInterval = 0
	t.Cleanup(func() { followInterval = previous })
	for _, tc := range []struct {
		state   string
		restart bool
	}{
		{statusStopped, false}, {statusFailed, false},
		{statusStopped, true}, {statusFailed, true}, {statusRunning, true}, {statusStopping, true},
	} {
		t.Run(fmt.Sprintf("%s/restart=%t", tc.state, tc.restart), func(t *testing.T) {
			const monitorID = "11111111-1111-4111-8111-111111111111"
			row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Status: tc.state, UpdateStatus: statusFailed,
				ConfigName:    "/tinfoil/containers/saved-digest",
				Config:        "containers: [{env: []}]",
				NetworkPolicy: &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}}
			var mutations []string
			client := newCPClient(cliConfig{ControlplaneURL: "https://cp.example"})
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
			_, err := startSandboxRow(testStreams(), client, row, tc.restart)
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
	const monitorID = "11111111-1111-4111-8111-111111111111"
	row := containerView{ID: "work-id", Name: "work", Repo: defaultSandboxRepo,
		Config: "containers: [{env: []}]"}
	peer := containerPeer{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid policy made a request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "test"})
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
			_, err := startSandboxRow(testStreams(), client, row, state == statusRunning)
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
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo, Status: statusRunning,
		OwnerKeyMode: "umk", OwnerPublicKey: owner, Volumes: map[string]string{sandboxWorkspaceSlot: workspaceID}}
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
	oldYes := commandState.sandboxActionOpts.sandboxYes
	commandState.sandboxActionOpts.sandboxYes = true
	t.Cleanup(func() { commandState.sandboxActionOpts.sandboxYes = oldYes })
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
	t.Cleanup(func() { commandState.sandboxDeleteCmd.SetErr(nil) })
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

func TestSandboxAttestationRelayUsesCurrentSchema(t *testing.T) {
	const instance = "22222222-2222-4222-8222-222222222222"
	const source = "acme/sandbox@v1"
	doc := []byte("attestation document")
	challenges := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			InstanceID string `json:"instance_id"`
			Nonce      string `json:"nonce"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nonce, err := hex.DecodeString(input.Nonce)
		if r.Method != http.MethodPost || r.URL.Path != "/sandboxes/relay" || input.InstanceID != instance || err != nil || len(nonce) != document.NonceSize {
			http.Error(w, "invalid attestation relay request", http.StatusBadRequest)
			return
		}
		challenges <- nonce
		json.NewEncoder(w).Encode(map[string]any{"status": http.StatusOK, "body": base64.RawURLEncoding.EncodeToString(doc)})
	}))
	defer server.Close()
	client := newCPClient(cliConfig{ControlplaneURL: server.URL})
	owner := sandboxOwner{instance: instance, request: func(method, path string, input, out any) error {
		_, err := client.do(method, path, nil, input, out)
		return err
	}}
	verificationError := errors.New("verification stopped")
	owner.verifyEvidence = func(raw, nonce []byte, reference string) (attestedEvidence, error) {
		require.Equal(t, doc, raw)
		require.Equal(t, <-challenges, nonce)
		require.Equal(t, source, reference)
		return nil, verificationError
	}
	_, err := owner.attest(source)
	require.ErrorIs(t, err, verificationError)
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
	profile := sshProfile{resourceID: "cp/org/user/resource", name: "work", hostName: routeName(boot), port: defaultSSHPort, user: sandboxLoginUser, identityFile: "/keys/my work/owner_ed25519", hostKey: boot, hostKeyAlias: "work.acme.sandboxes.tinfoil.dev",
		jump: monitorJump("work", "203.0.113.8", 22042, "/keys/personal", monitorKey, "personal.acme.monitors.tinfoil.dev")}

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

type fakeOwnerTransport struct {
	status sandboxStatus
	calls  []string
	bodies map[string]json.RawMessage
}

func (f *fakeOwnerTransport) reply(request ownerCall) any {
	f.calls = append(f.calls, request.Method+" "+request.Path)
	if f.bodies == nil {
		f.bodies = map[string]json.RawMessage{}
	}
	f.bodies[request.Path] = request.Body
	if request.Path == "/enroll" {
		var in struct {
			MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
			MonitorHostKey      string `json:"monitor_host_key"`
		}
		json.Unmarshal(request.Body, &in)
		agent := monitorIdentity(in.MonitorIdentitySeed)
		f.status.MonitorIdentity, f.status.MonitorHostKey, f.status.Volume = &agent, &in.MonitorHostKey, "unlocked"
	}
	return f.status
}

func TestSandboxEnrollDecidesFromMonitorIdentityAndSandboxStatus(t *testing.T) {
	instance := "22222222-2222-4222-8222-222222222222"
	volume := "33333333-3333-4333-8333-333333333333"
	monitorIdentitySeed, otherSeed := testSeed(t), testSeed(t)
	agent, other := monitorIdentity(monitorIdentitySeed), monitorIdentity(otherSeed)
	monitorHost, oldHost := testSigner(t).PublicKey(), authorizedLine(testSigner(t))
	host := authorizedKeyLine(monitorHost)
	for _, test := range []struct {
		name          string
		agent         *string
		volume        string
		pinned        *string
		monitorKnows  bool
		noLocalKeys   bool
		monitorEnroll bool
		calls         []string
		initialize    bool
		err           string
	}{
		{name: "first open", volume: "locked", monitorEnroll: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "rebooted sandbox", volume: "locked", monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "removed identity after Monitor-only restart", agent: &agent, volume: "unlocked", pinned: &oldHost, calls: []string{"GET /status"}, err: "no longer authorizes"},
		{name: "Monitor-only restart", agent: &agent, volume: "unlocked", pinned: &oldHost, monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "interrupted unlock", agent: &agent, volume: "locked", pinned: &host, monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "already enrolled", agent: &agent, volume: "unlocked", pinned: &host, monitorKnows: true, calls: []string{"GET /status"}},
		{name: "another identity", agent: &other, volume: "unlocked", monitorKnows: true, calls: []string{"GET /status"}, err: "different Monitor identity"},
		{name: "web-provisioned UMK", volume: "locked", noLocalKeys: true, monitorEnroll: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			seed := testSeed(t)
			signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
			require.NoError(t, err)
			owner := ed25519PublicKeyString(seed)
			transport := &fakeOwnerTransport{status: sandboxStatus{Protocol: sandboxOwnerProtocol, InstanceID: instance, Volume: test.volume, MonitorIdentity: test.agent, MonitorHostKey: test.pinned}}
			rpc, endpoint := testSandboxOwner(t, seed, transport.reply)
			rpc.instance = instance
			var monitorCalls []string
			m := &monitorSession{dir: t.TempDir(), hostKey: monitorHost, keys: &resourceKeys{}}
			if test.monitorKnows {
				m.view.Config.Identities = map[string]struct {
					Key string `json:"key"`
				}{"sandbox-work": {Key: agent}}
			}
			m.request = func(method, path string, input, out any) error {
				data, _ := json.Marshal(input)
				monitorCalls = append(monitorCalls, method+" "+path+" "+string(data))
				return nil
			}
			keys := &resourceKeys{mode: "tmk", signer: signer, monitorIdentitySeed: bytes.Clone(monitorIdentitySeed), storageKey: testSeed(t)}
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "user_owner"}
			if test.noLocalKeys {
				keys = &resourceKeys{mode: "umk", signer: signer}
				keys.umkPath, err = umkRecordPath(scope, "11111111-1111-4111-8111-111111111111")
				require.NoError(t, err)
			}
			s := &sandboxSession{box: containerView{Name: "work", OwnerPublicKey: owner}, keys: keys, monitor: m, expires: time.Now().Add(time.Hour),
				binding: mkBinding{Account: "personal", ContainerID: "11111111-1111-4111-8111-111111111111", InstanceID: &instance, VolumeID: &volume},
				owner:   rpc}
			err = s.enroll(testStreams(), t.Context())
			endpoint.mu.Lock()
			defer endpoint.mu.Unlock()
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.calls, transport.calls)
			require.Equal(t, test.monitorEnroll, len(monitorCalls) == 1, "Monitor calls: %v", monitorCalls)
			if test.monitorEnroll {
				enrolled := agent
				if test.noLocalKeys {
					enrolled = monitorIdentity(keys.monitorIdentitySeed)
				}
				require.Equal(t, `POST /enroll {"sandbox-work":{"key":"`+enrolled+`"}}`, monitorCalls[0], "only the public agent key goes to Monitor, never restored")
			}
			if enroll, ok := transport.bodies["/enroll"]; ok {
				var in struct {
					MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
					MonitorHostKey      string `json:"monitor_host_key"`
					DiskKey             b64u   `json:"disk_key"`
					AllowInitialize     bool   `json:"allow_initialize"`
				}
				require.NoError(t, json.Unmarshal(enroll, &in))
				require.Equal(t, test.initialize, in.AllowInitialize)
				require.Equal(t, host, in.MonitorHostKey)
				require.Equal(t, []byte(keys.storageKey), []byte(in.DiskKey))
			}
			_, statErr := os.Stat(keys.umkPath)
			require.Equal(t, test.noLocalKeys && test.err == "", statErr == nil, "UMK keys are generated only when missing")
		})
	}
}

func TestDirectProfileUnlocksOverAttestedOwnerSSH(t *testing.T) {
	seed := testSeed(t)
	host := testSigner(t)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	type invocation struct {
		command string
		body    []byte
	}
	calls := make(chan invocation, 16)
	var volume atomic.Value
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, global, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(global)
				channel, pending, err := (<-channels).Accept()
				if err != nil {
					return
				}
				defer channel.Close()
				request := <-pending
				var command struct{ Command string }
				if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
					request.Reply(false, nil)
					return
				}
				request.Reply(true, nil)
				body, err := io.ReadAll(channel)
				if err != nil {
					return
				}
				calls <- invocation{command.Command, body}
				if strings.HasSuffix(command.Command, "--status") {
					io.WriteString(channel, volume.Load().(string)+"\n")
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}()
		}
	}()
	address, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	for _, test := range []struct {
		volume, unlock string
		noLocalKeys    bool
	}{
		{volume: "locked", unlock: "/usr/local/bin/workspace-unlock --initialize"},
		{volume: "unlocked"},
		{volume: "locked", noLocalKeys: true, unlock: "/usr/local/bin/workspace-unlock --initialize"},
	} {
		t.Run(test.volume+fmt.Sprint(test.noLocalKeys), func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			volume.Store(test.volume)
			owner := ed25519PublicKeyString(seed)
			keys := &resourceKeys{mode: "tmk", signer: signer, storageKey: bytes.Repeat([]byte{0, 1, 2, 10}, 8)}
			if test.noLocalKeys {
				keys = &resourceKeys{mode: "umk", signer: signer}
				keys.umkPath, err = umkRecordPath(accountScope{ControlplaneURL: "https://cp.example", UserID: "user_owner"}, "11111111-1111-4111-8111-111111111111")
				require.NoError(t, err)
			}
			instance, volumeID := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
			s := &sandboxSession{box: containerView{Name: "work", Domain: "sandbox.invalid", OwnerPublicKey: owner}, keys: keys, noMonitor: true, expires: time.Now().Add(time.Hour),
				binding: mkBinding{Account: "personal", ContainerID: "11111111-1111-4111-8111-111111111111", InstanceID: &instance, VolumeID: &volumeID},
				profile: sshProfile{hostName: address, port: portNumber, hostKey: host.PublicKey()}}
			err := s.enroll(testStreams(), t.Context())
			require.NoError(t, err)
			status := <-calls
			require.Equal(t, "/usr/local/bin/workspace-unlock --status", status.command)
			require.Empty(t, status.body)
			if test.unlock == "" {
				require.Empty(t, calls)
				return
			}
			unlock := <-calls
			require.Equal(t, test.unlock, unlock.command)
			require.Equal(t, []byte(keys.storageKey), unlock.body, "only the raw volume key goes to workspace-unlock")
			require.Empty(t, calls)
		})
	}
}

func TestUnlockRequiresUnexpiredAttestationBeforeDial(t *testing.T) {
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		for _, noMonitor := range []bool{false, true} {
			session := sandboxSession{expires: expiry, noMonitor: noMonitor, keys: &resourceKeys{}, profile: sshProfile{hostKey: testHostKey(t)}}
			require.ErrorContains(t, session.enroll(testStreams(), t.Context()), "attestation expired")
		}
	}
}

func TestMonitorRestartRelinksOnlyAuthorizedSandboxes(t *testing.T) {
	commandState := newCommandFixture()

	keys := &keyStateServer{}
	const monitorID = "99999999-9999-4999-8999-999999999999"
	type fixture struct {
		name, id, instance, volume string
		key                        mkResource
		host                       ssh.Signer
		owner                      *fakeSandboxOwner
		status                     sandboxStatus
		monitor                    string
	}
	monitorSigner := testSigner(t)
	newHost, oldHost := monitorSigner.PublicKey(), authorizedLine(testSigner(t))
	routes := map[string]string{}
	fixtures := map[string]*fixture{}
	var rows []containerView
	for i, name := range []string{"a", "b", "removed", "nokeys", "unbound", "wrongbinding", "rebooted", "elsewhere", "untrusted"} {
		f := &fixture{name: name, id: fmt.Sprintf("1111111%d-1111-4111-8111-111111111111", i), instance: fmt.Sprintf("2222222%d-2222-4222-8222-222222222222", i),
			volume: fmt.Sprintf("3333333%d-3333-4333-8333-333333333333", i), key: newResourceKey("sandbox"), host: testSigner(t), monitor: monitorID}
		agent := monitorIdentity(f.key.MonitorIdentitySeed)
		f.status = sandboxStatus{Protocol: sandboxOwnerProtocol, InstanceID: f.instance, Volume: "unlocked", MonitorIdentity: &agent, MonitorHostKey: &oldHost}
		if name == "rebooted" {
			f.status.MonitorIdentity = nil
		}
		if name == "elsewhere" {
			f.monitor = "88888888-8888-4888-8888-888888888888"
		}
		f.owner = &fakeSandboxOwner{owner: ed25519.NewKeyFromSeed(f.key.OwnerSeed).Public().(ed25519.PublicKey), reply: func(r ownerCall) any {
			if r.Path == "/enroll" {
				body := r.Body
				var in struct {
					MonitorHostKey string `json:"monitor_host_key"`
				}
				if err := json.Unmarshal(body, &in); err != nil {
					t.Error(err)
					return nil
				}
				f.status.MonitorHostKey = &in.MonitorHostKey
			}
			return f.status
		}}
		routes[net.JoinHostPort(routeName(f.host.PublicKey()), strconv.Itoa(defaultSSHPort))] = testSandboxSSH(t, f.host, f.owner)
		config := fmt.Sprintf("containers: [{env: [{SANDBOX_OWNER_PUBLIC_KEY: %q}, {SANDBOX_INSTANCE_ID: %q}]}]", f.key.OwnerPublicKey, f.instance)
		rows = append(rows, containerView{ID: f.id, Name: name, Repo: defaultSandboxRepo, Status: statusRunning, ClerkUserID: "user_owner", Config: config,
			Domain: name + ".example", ConfigName: "/tinfoil/containers/" + storageHash([]byte(config)),
			OwnerKeyMode: "tmk", OwnerPublicKey: f.key.OwnerPublicKey, Volumes: map[string]string{"workspace": f.volume},
			NetworkPolicy: &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: f.monitor, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}})
		fixtures[f.instance] = f
		fixtures[name] = f
	}
	var changedCreator atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/containers":
			json.NewEncoder(w).Encode(rows)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/containers/"):
			for _, row := range rows {
				if r.URL.Path == "/api/containers/"+row.ID {
					if changedCreator.Load() && row.Name == "a" {
						row.ClerkUserID = "user_changed"
					}
					json.NewEncoder(w).Encode(row)
					return
				}
			}
			http.NotFound(w, r)
		default:
			keys.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	cp, scope, _ := testLogin(t, server, keys)
	t.Setenv("HOME", t.TempDir())
	mk, err := newMKSession(cp, scope)
	require.NoError(t, err)
	_, err = mk.update(t.Context(), func(p *mkPayload) error {
		for _, name := range []string{"a", "b", "removed", "unbound", "wrongbinding", "rebooted", "elsewhere", "untrusted"} {
			f := fixtures[name]
			key := f.key
			if name != "unbound" {
				volume := f.volume
				if name == "wrongbinding" {
					volume = "44444444-4444-4444-8444-444444444444"
				}
				key.Binding = &mkBinding{Account: "personal", ContainerID: f.id, InstanceID: &f.instance, VolumeID: &volume}
			}
			if err := addKey(p, key); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
	revision := keys.revision

	var trusted []string
	for _, row := range rows {
		if row.Name != "untrusted" {
			target, err := parseConnectionDescriptor(connectionDescriptor{URL: "https://" + row.Domain, ConfigName: row.ConfigName, ConfigDigest: storageHash([]byte(row.Config))})
			require.NoError(t, err)
			trusted = append(trusted, target.source)
		}
	}
	policy, err := json.Marshal(map[string]any{"mode": "frozen", "allow": map[string]any{"pins": trusted}})
	require.NoError(t, err)
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), policy, 0o600))
	commandState.rootOpts.dependencies.verifySandboxEvidence = func(doc, _ []byte, source string) (attestedEvidence, error) {
		for _, f := range fixtures {
			if strings.Contains(string(doc), f.instance) && strings.Contains(source, storageHash(doc)) {
				host, err := x509.MarshalPKIXPublicKey(f.host.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey())
				require.NoError(t, err)
				return &testEvidence{expires: time.Now().Add(time.Hour), keys: []document.CryptoMaterialItem{
					{ID: "host-ssh", Format: document.KeySPKIV1Format, Data: hex.EncodeToString(host)},
				}}, nil
			}
		}
		return nil, errors.New("unknown evidence")
	}

	relayed := map[string]int{}
	var monitorCalls []string
	m := &monitorSession{dir: t.TempDir(), domain: "monitor.example", hostKey: newHost, keys: &resourceKeys{}}
	device, err := ensureSSHIdentity(filepath.Join(m.dir, monitorDeviceKeyName), nil)
	require.NoError(t, err)
	m.address = testSandboxRoutes(t, monitorSigner, device.PublicKey(), routes)
	m.view.Config.Identities = map[string]struct {
		Key string `json:"key"`
	}{}
	for _, name := range []string{"a", "b", "nokeys", "unbound", "wrongbinding", "rebooted", "elsewhere", "untrusted"} {
		m.view.Config.Identities["sandbox-"+name] = struct {
			Key string `json:"key"`
		}{monitorIdentity(fixtures[name].key.MonitorIdentitySeed)}
	}
	m.request = func(method, path string, input, out any) error {
		raw, _ := json.Marshal(input)
		if path != "/sandboxes/relay" {
			monitorCalls = append(monitorCalls, method+" "+path)
			return errors.New("re-linking must only use the relay")
		}
		require.NotContains(t, string(raw), "monitor_host_key", "Monitor sees only sealed owner requests")
		var in struct {
			InstanceID string `json:"instance_id"`
			Nonce      string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(raw, &in))
		f := fixtures[in.InstanceID]
		relayed[f.name]++
		if in.Nonce != "" {
			config := rows[slices.IndexFunc(rows, func(r containerView) bool { return r.ID == f.id })].Config
			return json.Unmarshal(fmt.Appendf(nil, `{"status":200,"headers":{},"body":%q}`, base64.RawURLEncoding.EncodeToString([]byte(config))), out)
		}
		return errors.New("only attestation uses the HTTP relay")
	}

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	profiles := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(profiles, 0o700))
	resourceID := scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + fixtures["a"].id
	require.NoError(t, os.WriteFile(filepath.Join(profiles, "a-alias.conf"), []byte("# tinfoil-resource: "+resourceID+"\nHost a-alias\n"), 0o600))

	failures := relinkSandboxes(testStreams(), commandState.identityOpts, commandState.rootOpts, commandState.trustOpts, t.Context(), scope, cp, m, monitorID)
	var reported []string
	for _, failure := range failures {
		reported = append(reported, failure.Error())
	}
	require.Len(t, failures, 3, "%v", reported)
	all := strings.Join(reported, "\n")
	require.Contains(t, all, "sandbox wrongbinding:")
	require.Contains(t, all, "no longer matches")
	require.Contains(t, all, "sandbox rebooted: its saved Monitor identity is not active")
	require.Contains(t, all, "sandbox untrusted: config")
	require.Contains(t, all, "is not allowed")
	host := authorizedKeyLine(newHost)
	for _, name := range []string{"a", "b"} {
		f := fixtures[name]
		f.owner.mu.Lock()
		require.Equal(t, host, *f.status.MonitorHostKey, name)
		f.owner.mu.Unlock()
		var paths []string
		for _, request := range f.owner.calls() {
			paths = append(paths, request.Method+" "+request.Path)
		}
		require.Equal(t, []string{"GET /status", "POST /enroll"}, paths, name)
	}
	require.Equal(t, []string{"GET /status"}, []string{fixtures["rebooted"].owner.calls()[0].Method + " " + fixtures["rebooted"].owner.calls()[0].Path})
	require.Len(t, fixtures["rebooted"].owner.calls(), 1, "a rebooted sandbox is not enrolled or unlocked here")
	for _, name := range []string{"removed", "nokeys", "unbound", "wrongbinding", "elsewhere", "untrusted"} {
		require.Zero(t, relayed[name], "%s is not contacted", name)
	}
	require.Empty(t, monitorCalls, "no Monitor enrollment, unlock or restore")
	require.Equal(t, revision, keys.revision, "re-linking never writes the key bundle")

	pins, err := os.ReadFile(filepath.Join(profiles, "a-alias.known_hosts"))
	require.NoError(t, err)
	require.Contains(t, string(pins), "monitor.example "+strings.TrimSpace(authorizedKeyLine(newHost)), "the installed jump profile pins the new Monitor key")
	conf, err := os.ReadFile(filepath.Join(profiles, "a-alias.conf"))
	require.NoError(t, err)
	require.Contains(t, string(conf), "ProxyJump a-alias.monitor")
	require.NoFileExists(t, filepath.Join(profiles, "b.conf"), "re-linking installs no new profile")

	// A second open finds every pin current and changes nothing.
	for _, name := range []string{"a", "b"} {
		fixtures[name].owner.reset()
	}
	require.Len(t, relinkSandboxes(testStreams(), commandState.identityOpts, commandState.rootOpts, commandState.trustOpts, t.Context(), scope, cp, m, monitorID), 3)
	for _, name := range []string{"a", "b"} {
		require.Len(t, fixtures[name].owner.calls(), 1, "%s: status only", name)
	}

	for _, tc := range []struct {
		name, mode, want string
		changedCreator   bool
	}{
		{name: "changed creator in fresh detail", mode: "tmk", changedCreator: true, want: "inventory changed"},
		{name: "unsupported custody pairing", mode: "umk", want: "a UMK Monitor cannot serve the synced sandbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedCreator.Store(tc.changedCreator)
			m.keys.mode = tc.mode
			before := relayed["a"]
			err := relinkSandbox(testStreams(), commandState.identityOpts, commandState.rootOpts, commandState.trustOpts, t.Context(), scope, cp, m, monitorID, fixtures["a"].id)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, before, relayed["a"], "invalid ownership or custody must not contact the sandbox")
			require.Equal(t, revision, keys.revision, "re-linking does not change key state")
		})
	}
}
