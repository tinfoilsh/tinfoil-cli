package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testBootKey(t *testing.T) ssh.PublicKey {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(&private.PublicKey)
	require.NoError(t, err)
	return key
}

func TestContainedProfileJumpsThroughMonitorAndKeepsItsAlias(t *testing.T) {
	program, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client unavailable")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	boot, monitorKey := testBootKey(t), testHostKey(t)
	profile := sshProfile{name: "work", hostName: routeName(boot), port: defaultSSHPort, user: sandboxLoginUser, identityFile: "/keys/work/id_ed25519", hostKey: boot, hostKeyAlias: "work.acme.sandboxes.tinfoil.dev",
		jump: &sshProfile{name: "work" + monitorJumpSuffix, hostName: "203.0.113.8", port: 22042, user: monitorSSHUser, identityFile: "/keys/personal/device_ed25519", hostKey: monitorKey, hostKeyAlias: "personal.acme.monitors.tinfoil.dev"}}

	other := []byte("Host work\n  HostName work.example\n  IdentityFile ~/.ssh/id_work\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), other, 0o600))
	require.ErrorContains(t, installSandboxAlias(profile, home), "profile of another host")
	kept, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Equal(t, other, kept, "another host keeps its alias")

	require.NoError(t, os.Remove(filepath.Join(dir, "work.conf")))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host existing\n  User me\n"), 0o600))
	require.NoError(t, installSandboxAlias(profile, home))
	config, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	require.NoError(t, err)
	require.Equal(t, sshIncludeLine()+"\n\nHost existing\n  User me\n", string(config))

	rebooted := testBootKey(t)
	profile.hostName, profile.hostKey = routeName(rebooted), rebooted
	require.NoError(t, installSandboxAlias(profile, home), "a new boot replaces this sandbox's own profile")

	path := filepath.Join(dir, "work.conf")
	for host, expected := range map[string][]string{
		"work":         {"hostname " + strings.ToLower(routeName(rebooted)), "proxyjump work.monitor", "hostkeyalias work.acme.sandboxes.tinfoil.dev", "user sandbox", "stricthostkeychecking true"},
		"work.monitor": {"hostname 203.0.113.8", "port 22042", "hostkeyalias personal.acme.monitors.tinfoil.dev", "identityfile /keys/personal/device_ed25519"},
	} {
		data, err := exec.Command(program, "-G", "-F", path, host).Output()
		require.NoError(t, err)
		for _, want := range expected {
			require.Contains(t, string(data), want+"\n", host)
		}
	}
	pins, err := knownhosts.New(filepath.Join(dir, "work.known_hosts"))
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: defaultSSHPort}
	require.NoError(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, rebooted))
	require.NoError(t, pins("personal.acme.monitors.tinfoil.dev:22", remote, monitorKey))
	require.Error(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, boot), "the previous boot is no longer trusted")
	require.Error(t, pins("work.acme.sandboxes.tinfoil.dev:22", remote, monitorKey), "Monitor cannot impersonate the sandbox")
}

func TestContainedKeysServeOneAccountAndMonitor(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	personal := sandboxBinding{accountScope{ControlplaneURL: "https://api.tinfoil.sh", OrgID: "org_a", UserID: "user_1"}, "personal"}
	elsewhere := personal
	elsewhere.Scope.OrgID = "org_b"

	_, err := containedKeys("work", personal, false)
	require.ErrorContains(t, err, "tinfoil monitor import")
	keys, err := containedKeys("work", personal, true)
	require.NoError(t, err)
	require.NotEmpty(t, keys.agentKey)
	again, err := containedKeys("work", personal, false)
	require.NoError(t, err)
	require.Equal(t, keys, again, "keys are made once and reused")
	_, err = containedKeys("work", elsewhere, true)
	require.ErrorContains(t, err, "another account")

	require.NoError(t, os.Remove(filepath.Join(keys.dir, sandboxAgentKeyName)))
	for _, create := range []bool{false, true} {
		_, err = containedKeys("work", personal, create)
		require.ErrorIs(t, err, os.ErrNotExist, "a remote resource may hold a bound key")
	}
	require.NoFileExists(t, filepath.Join(keys.dir, sandboxAgentKeyName))

	interrupted, err := sandboxKeyDir("fresh")
	require.NoError(t, err)
	require.NoError(t, prepareStorageDirectory(interrupted))
	agent, err := ensureSSHKey(filepath.Join(interrupted, sandboxAgentKeyName))
	require.NoError(t, err)
	finished, err := containedKeys("fresh", personal, true)
	require.NoError(t, err, "a creation interrupted before binding, so before anything remote, finishes its keys")
	require.Equal(t, agent, finished.agentKey)

	_, err = ensureSandboxKeys("old")
	require.NoError(t, err)
	_, err = containedKeys("old", personal, true)
	require.ErrorContains(t, err, "earlier sandbox", "an unbound sandbox's keys are never adopted")
}

func TestSendEnrollmentRetriesLostReply(t *testing.T) {
	var bodies [][]byte
	var mu sync.Mutex
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		mu.Lock()
		bodies = append(bodies, body)
		first := len(bodies) == 1
		mu.Unlock()
		if first {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			conn.Close()
			return
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	keys := &sandboxKeys{dir: t.TempDir(), publicKey: "ssh-ed25519 AAAA", diskKey: "disk", monitor: &monitorAgentConfig{Domain: "personal.example", IP: "100.64.0.1", Port: 18293, HostKey: "ssh-ed25519 BBBB", Identity: "agent"}}

	require.NoError(t, sendEnrollment(server.Client(), server.URL, keys))
	require.Len(t, bodies, 2)
	require.True(t, bytes.Equal(bodies[0], bodies[1]), "a lost reply is retried with the identical enrollment")
	var sent struct {
		Monitor monitorAgentConfig `json:"monitor"`
	}
	require.NoError(t, json.Unmarshal(bodies[1], &sent))
	require.Equal(t, *keys.monitor, sent.Monitor)

	bodies, status = nil, http.StatusConflict
	require.ErrorContains(t, sendEnrollment(server.Client(), server.URL, keys), "already has an owner")
}

func TestEnrollmentClientRequiresFreshPinnedAttestation(t *testing.T) {
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	var mu sync.Mutex
	served, closed := map[net.Conn]bool{}, make(chan struct{}, 1)
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		served[conn] = served[conn] || state == http.StateActive
		if state == http.StateClosed && served[conn] {
			closed <- struct{}{}
		}
	}
	server.StartTLS()
	defer server.Close()
	fingerprint, err := enclave.ConnectionCertFP(tls.ConnectionState{PeerCertificates: []*x509.Certificate{server.Certificate()}})
	require.NoError(t, err)
	client := func(pin string, expires time.Time) *http.Client {
		transport := server.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: pinnedTLS(pin)}
		return &http.Client{Transport: freshAttestation{transport, expires}}
	}

	_, err = client("another key", time.Now().Add(time.Minute)).Get(server.URL)
	require.ErrorContains(t, err, "does not match the attested key")
	_, err = client(fingerprint, time.Time{}).Get(server.URL)
	require.ErrorContains(t, err, "no unexpired freshness", "an attestation without freshness authorizes nothing")
	require.Zero(t, requests)

	expires := time.Now().Add(300 * time.Millisecond)
	fresh := client(fingerprint, expires)
	resp, err := fresh.Get(server.URL)
	require.NoError(t, err)
	resp.Body.Close()
	time.Sleep(time.Until(expires))
	_, err = fresh.Get(server.URL)
	require.ErrorContains(t, err, "no unexpired freshness", "a pooled connection is not reused after expiry")
	require.Equal(t, 1, requests)
	fresh.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the pooled connection outlives the enrollment, holding its private connection open")
	}
}

func TestDeleteRetryRemovesAccessOfGoneSandbox(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/context" {
			io.WriteString(w, `{"context_type":"organization","organization":{"id":"org_1"},"user_id":"user_1"}`)
			return
		}
		require.Equal(t, http.MethodGet, r.Method)
		http.Error(w, `{"error":"sandbox not found"}`, http.StatusNotFound)
	}))
	defer server.Close()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	sandboxYes = true
	t.Cleanup(func() { sandboxYes = false })
	keys, err := containedKeys("work", sandboxBinding{accountScope{ControlplaneURL: server.URL, OrgID: "org_1", UserID: "user_1"}, "personal"}, true)
	require.NoError(t, err)
	profile := sshProfile{name: "work", hostName: "route.sandbox.invalid", port: defaultSSHPort, user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: testBootKey(t)}
	require.NoError(t, profile.installTo(home, strings.NewReader(""), io.Discard, false, true))

	err = sandboxDeleteCmd.RunE(sandboxDeleteCmd, []string{"work"})
	require.ErrorContains(t, err, "Monitor identity sandbox-work may remain", "a retry still reaches the Monitor cleanup")
	require.NoFileExists(t, filepath.Join(home, ".ssh", "tinfoil", "work.conf"))
	again, err := containedKeys("work", sandboxBinding{accountScope{ControlplaneURL: server.URL, OrgID: "org_1", UserID: "user_1"}, "personal"}, false)
	require.NoError(t, err)
	require.Equal(t, keys, again, "recovery keys stay")
	require.ErrorContains(t, sandboxDeleteCmd.RunE(sandboxDeleteCmd, []string{"other"}), "404", "a sandbox this device never bound is just not found")
}

func TestCreateResumesOnlyItsOwnContainedSandbox(t *testing.T) {
	monitor, state := "other", sandboxStateRunning
	template := "containers:\n  - name: workspace\n    env: [SANDBOX_OWNER_KEY_SHA256]\n"
	var ownerDigest string
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, r.Method+" "+r.URL.Path+" "+string(body))
		route := r.Method + " " + r.URL.Path
		switch {
		case strings.HasSuffix(route, "/tinfoil-config.yml"):
			io.WriteString(w, template)
		case route == "GET /api/auth/context":
			io.WriteString(w, `{"context_type":"organization","organization":{"id":"org_1"},"user_id":"user_1"}`)
		case route == "GET /api/containers":
			io.WriteString(w, `[{"id":"personal-id","name":"personal"},{"id":"work-id","name":"work"}]`)
		case route == "GET /api/containers/personal-id":
			io.WriteString(w, `{"id":"personal-id","name":"personal"}`)
		case route == "GET /api/containers/work-id":
			rendered, err := renderTemplateEnv([]byte(template), map[string]string{sandboxOwnerEnv: ownerDigest})
			require.NoError(t, err)
			json.NewEncoder(w).Encode(containerView{CurrentTag: "v1", Config: string(rendered), ID: "work-id", Name: "work", Repo: defaultSandboxRepo, Domain: "work.example", Status: state, NetworkPolicy: &containerNetworkPolicy{Egress: []containerPeer{{monitor + "-id", 22}}}})
		default:
			http.Error(w, `{"error":"unexpected"}`, http.StatusTeapot)
		}
	}))
	defer server.Close()
	oldBase := sandboxTemplateBase
	sandboxTemplateBase = server.URL
	t.Cleanup(func() { sandboxTemplateBase = oldBase })
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	sandboxMonitor = "personal"
	t.Cleanup(func() { sandboxMonitor = "" })
	create := func() error { return sandboxCreateCmd.RunE(sandboxCreateCmd, []string{"work"}) }

	require.ErrorContains(t, create(), "no local owner credential", "a sandbox this device never bound is not taken over")
	keys, err := containedKeys("work", sandboxBinding{accountScope{ControlplaneURL: server.URL, OrgID: "org_1", UserID: "user_1"}, "personal"}, true)
	require.NoError(t, err)
	ownerBytes, err := base64.StdEncoding.DecodeString(keys.diskKey)
	require.NoError(t, err)
	ownerDigest = storageHash(ownerBytes)
	state, requests = sandboxStateStopped, nil
	require.ErrorContains(t, create(), "start it with `tinfoil sandbox start work`", "create never starts an existing sandbox")
	for _, request := range requests {
		require.True(t, strings.HasPrefix(request, "GET "), "a stopped sandbox is only read: %s", request)
	}
	state = sandboxStateRunning
	require.ErrorContains(t, create(), "not contained by Monitor personal", "the control plane's binding must agree")

	monitor = "personal"
	resume, err := registerSandboxAgent("work", "personal")
	require.NoError(t, err)
	require.True(t, resume)
	for _, request := range requests {
		require.True(t, strings.HasPrefix(request, "GET "), request)
	}
}
