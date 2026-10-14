package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
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
