package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
			_, err := startSandboxRow(client, row, tc.restart)
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
			_, err := startSandboxRow(client, row, state == statusRunning)
			require.ErrorContains(t, err, "TCP alias")
		}
	}
	row.NetworkPolicy = &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{peer}}
	require.NoError(t, validateSandboxNetwork(row))
}

func TestSandboxDeleteKeepsCredentialsAndRemovesOwnedProfile(t *testing.T) {
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo, Status: statusRunning}
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
	configureContainerPromotionTest(t, server.URL)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldYes := sandboxYes
	sandboxYes = true
	t.Cleanup(func() { sandboxYes = oldYes })
	profile := filepath.Join(home, ".ssh", "tinfoil", "work.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(profile), 0700))
	require.NoError(t, os.WriteFile(profile, []byte("# tinfoil-resource: "+server.URL+"//owner/"+row.ID+"\n"), 0600))
	dir, err := resourceDir(accountScope{ControlplaneURL: server.URL, UserID: "owner"}, row.ID)
	require.NoError(t, err)
	credential := filepath.Join(dir, sandboxDiskKeyName)
	require.NoError(t, writeStorageJSON(credential, testOwnerCredential(t), false))
	before, err := os.ReadFile(credential)
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, sandboxDeleteCmd.RunE(sandboxDeleteCmd, []string{row.Name}))
	}
	after, err := os.ReadFile(credential)
	require.NoError(t, err)
	require.Equal(t, before, after, "deletion must preserve encryption and owner signing keys")
	require.NoFileExists(t, profile)
}

func TestSandboxAttestationRejectsUntrustedRelayReplies(t *testing.T) {
	nonces := map[string]bool{}
	for _, tt := range []struct {
		name, body, wantError string
		status                int
	}{
		{"forged evidence", `{}`, "verifying sandbox.invalid", http.StatusOK},
		{"redirect", "", "302 Found", http.StatusFound},
		{"oversized evidence", strings.Repeat("x", maxSandboxAttestationBytes+1), "exceeds", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requests := make(chan *http.Request, 1)
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if count.Add(1) == 1 {
					requests <- r
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer server.Close()
			dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			key, expiry, err := attestConnection(dial, "sandbox.invalid", defaultSandboxRepo)
			require.ErrorContains(t, err, tt.wantError)
			require.Nil(t, key)
			require.True(t, expiry.IsZero())
			require.EqualValues(t, 1, count.Load(), "redirects must not be followed")
			request := <-requests
			require.Nil(t, request.TLS)
			require.Equal(t, http.MethodGet, request.Method)
			require.Equal(t, sandboxAttestationPath, request.URL.Path)
			require.Zero(t, request.ContentLength)
			for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
				require.Empty(t, request.Header.Get(header))
			}
			require.Len(t, request.URL.Query(), 1)
			nonce := request.URL.Query().Get("nonce")
			raw, err := hex.DecodeString(nonce)
			require.NoError(t, err)
			require.Len(t, raw, 32)
			require.False(t, nonces[nonce], "each attempt must use fresh evidence")
			nonces[nonce] = true
		})
	}
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
	require.ErrorContains(t, installSandboxAlias(profile, home), "profile of another resource")
	kept, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Equal(t, other, kept, "another host keeps its alias")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), []byte("# tinfoil-resource: cp/org/user/resource\nHost work\n"), 0600))
	require.NoError(t, installSandboxAlias(profile, home))
	updated, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Contains(t, string(updated), "IdentityFile \"/keys/my work/owner_ed25519\"\n")

	rebooted := testHostKey(t)
	profile.hostName, profile.hostKey = routeName(rebooted), rebooted
	require.NoError(t, installSandboxAlias(profile, home), "a new boot replaces this sandbox's own profile")

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

func TestSandboxSetupSeparatesMonitorCredentialsAndWorkspaceUnlock(t *testing.T) {
	credential := testOwnerCredential(t)
	owner := testHostKey(t)
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
	var failure atomic.Int32
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
				status := uint32(0)
				switch failure.Load() {
				case 1:
					return // Reply lost: the CLI must report it, without retrying.
				case 2:
					channel.Stderr().Write([]byte("request refused"))
					status = 1
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			}()
		}
	}()
	dial := func() (*ssh.Client, error) {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			return nil, err
		}
		return connectOwnerSSHAs(conn, "sandbox.invalid", host.PublicKey(), credential.SigningSeed, sandboxLoginUser)
	}
	private, err := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)), "agent")
	require.NoError(t, err)
	volumeKey := bytes.Repeat([]byte{0, 1, 2, 10}, 16)
	keys := &sandboxKeys{diskKey: volumeKey, monitorIdentity: string(pem.EncodeToMemory(private))}
	monitorKey := string(ssh.MarshalAuthorizedKey(host.PublicKey()))
	directory := t.TempDir()
	running := filepath.Join(directory, "systemd")
	restarted := filepath.Join(directory, "restarted")
	systemctl := filepath.Join(directory, "systemctl")
	require.NoError(t, os.WriteFile(systemctl, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(restarted)+"\n"), 0o700))
	install := func(call invocation) {
		require.Equal(t, []byte(keys.monitorIdentity), call.body, "only the private identity goes on stdin")
		// Run the actual installation script with this user's temporary directory.
		script := strings.NewReplacer("sudo -n ", "", "/run/monitor", directory,
			"-g sandbox", fmt.Sprintf("-g %d", os.Getgid()),
			"sandbox:sandbox", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"/run/systemd/system", running, "systemctl restart", systemctl+" restart").Replace(call.command)
		process := exec.Command("sh", "-c", script)
		process.Stdin = bytes.NewReader(call.body)
		output, err := process.CombinedOutput()
		require.NoError(t, err, string(output))
		for name, want := range map[string]string{"identity": keys.monitorIdentity, "known_hosts": "monitor " + monitorKey} {
			data, err := os.ReadFile(filepath.Join(directory, name))
			require.NoError(t, err)
			require.Equal(t, want, string(data))
			info, err := os.Stat(filepath.Join(directory, name))
			require.NoError(t, err)
			require.EqualValues(t, 0o600, info.Mode().Perm())
		}
	}
	require.NoError(t, configureSandbox(dial, keys, monitorKey, true))
	install(<-calls)
	require.NoFileExists(t, restarted, "initial setup runs before systemd")
	unlock := <-calls
	require.Contains(t, unlock.command, "workspace-unlock --initialize")
	require.Equal(t, volumeKey, unlock.body, "only the raw volume key goes to workspace-unlock")
	require.Empty(t, calls)

	// A Monitor reboot restores credentials and checks whether the disk is mounted.
	require.NoError(t, os.Mkdir(running, 0o700))
	monitorKey = string(ssh.MarshalAuthorizedKey(owner))
	suppliedKey := strings.TrimSpace(monitorKey) + " comment '$(touch " + filepath.Join(directory, "injected") + ")'\nignored extra line\n"
	require.NoError(t, configureSandbox(dial, keys, suppliedKey, false))
	install(<-calls)
	unlock = <-calls
	require.NotContains(t, unlock.command, "--initialize")
	require.Equal(t, volumeKey, unlock.body, "a Monitor-only reboot still attempts workspace unlock")
	require.NoFileExists(t, filepath.Join(directory, "injected"))
	output, err := os.ReadFile(restarted)
	require.NoError(t, err)
	require.Equal(t, "restart monitor-network.service\n", string(output))
	require.Empty(t, calls)

	for _, mode := range []int32{1, 2} {
		failure.Store(mode)
		err := configureSandbox(dial, keys, monitorKey, false)
		require.ErrorContains(t, err, "install Monitor credentials")
		if mode == 2 {
			require.ErrorContains(t, err, "request refused")
		}
		<-calls
		require.Empty(t, calls, "a failed setup must not retry or send the volume key")
	}
}

func TestUnlockRequiresUnexpiredAttestationBeforeDial(t *testing.T) {
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		session := sandboxSession{expires: expiry, keys: &sandboxKeys{dir: t.TempDir()}, profile: sshProfile{hostKey: testHostKey(t)}}
		session.monitorKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(session.profile.hostKey)))
		require.NoError(t, writeStorageJSON(filepath.Join(session.keys.dir, sandboxEnrolledKeyName), map[string]string{
			"boot_key": session.monitorKey, "monitor_key": session.monitorKey,
		}, false))
		require.ErrorContains(t, session.enroll(), "attestation expired")
	}
}
