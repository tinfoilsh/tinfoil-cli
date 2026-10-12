package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
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
	profile := sshProfile{resourceID: "cp/org/user/resource", name: "work", hostName: routeName(boot), port: defaultSSHPort, user: sandboxLoginUser, identityFile: "/keys/my work/owner_ed25519", hostKey: boot, hostKeyAlias: "work.acme.sandboxes.tinfoil.dev",
		jump: &sshProfile{name: "work" + monitorJumpSuffix, hostName: "203.0.113.8", port: 22042, user: monitorSSHUser, identityFile: "/keys/personal/device_ed25519", hostKey: monitorKey, hostKeyAlias: "personal.acme.monitors.tinfoil.dev"}}

	other := []byte("Host work\n  HostName work.example\n  IdentityFile ~/.ssh/id_work\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), other, 0o600))
	require.ErrorContains(t, installSandboxAlias(profile, home), "profile of another resource")
	kept, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Equal(t, other, kept, "another host keeps its alias")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), []byte("# tinfoil-resource: cp/org/user/resource\nHost work\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host existing\n  User me\n"), 0o600))
	require.NoError(t, installSandboxAlias(profile, home))
	updated, err := os.ReadFile(filepath.Join(dir, "work.conf"))
	require.NoError(t, err)
	require.Contains(t, string(updated), "IdentityFile \"/keys/my work/owner_ed25519\"\n")
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

func TestProfileOwnershipUsesAccountAndResource(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh", "tinfoil")
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.conf"), []byte("# tinfoil-resource: cp/org/user/one\n"), 0600))
	owned, err := ownsSSHProfile(home, "work", "cp/org/user/one")
	require.NoError(t, err)
	require.True(t, owned)
	for _, other := range []string{"cp/org/user/two", "cp/other/user/one", "other/org/user/one"} {
		owned, err = ownsSSHProfile(home, "work", other)
		require.NoError(t, err)
		require.False(t, owned)
	}
	require.NoError(t, forgetSandbox("work", ""))
}

func TestSandboxPeerRequiresOneUsablePrivateSSHPeer(t *testing.T) {
	var endpoint sandboxEndpoint
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/api/containers/work/network":
			json.NewEncoder(w).Encode(map[string]any{"egress": []sandboxEndpoint{endpoint}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "test"})
	for _, policy := range []*containerNetworkPolicy{nil, {}, {Public: true}, {EgressMode: "unrestricted"}, {Egress: []containerPeer{{"peer", 443}}}, {Egress: []containerPeer{{"peer", 22}, {"other", 22}}}} {
		_, err := sandboxPeer(client, containerView{ID: "work", NetworkPolicy: policy})
		require.Error(t, err)
	}
	require.Zero(t, requests.Load())
	row := containerView{ID: "work", NetworkPolicy: &containerNetworkPolicy{Egress: []containerPeer{{"peer", 22}}}}
	for _, endpoint = range []sandboxEndpoint{{"invalid", 22}, {"100.64.0.1", 0}, {"100.64.0.1", 65536}} {
		_, err := sandboxPeer(client, row)
		require.Error(t, err)
	}
	endpoint = sandboxEndpoint{"100.64.0.1", 22}
	got, err := sandboxPeer(client, row)
	require.NoError(t, err)
	require.Equal(t, endpoint, got)
}
