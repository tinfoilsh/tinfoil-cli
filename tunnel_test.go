package main

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSplitSSHArgs(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		wantOptions []string
		wantCommand []string
	}{
		{args: nil},
		{args: []string{"-A", "-L", "5432:localhost:5432"}, wantOptions: []string{"-A", "-L", "5432:localhost:5432"}},
		{args: []string{"systemctl", "status"}, wantCommand: []string{"systemctl", "status"}},
		{args: []string{"-t", "-p2022", "top", "-b"}, wantOptions: []string{"-t", "-p2022"}, wantCommand: []string{"top", "-b"}},
		{args: []string{"-o", "ServerAliveInterval=30", "uptime"}, wantOptions: []string{"-o", "ServerAliveInterval=30"}, wantCommand: []string{"uptime"}},
		{args: []string{"-l", "root", "-J", "jump", "id"}, wantOptions: []string{"-l", "root", "-J", "jump"}, wantCommand: []string{"id"}},
	} {
		options, command := splitSSHArgs(tc.args)
		if !slices.Equal(options, tc.wantOptions) || !slices.Equal(command, tc.wantCommand) {
			t.Errorf("splitSSHArgs(%q) = %q, %q; want %q, %q", tc.args, options, command, tc.wantOptions, tc.wantCommand)
		}
	}
}

func TestProxyCommandNamesResolvedHost(t *testing.T) {
	withRepo, err := proxyCommand(&rootOptions{}, &tunnelOptions{}, &tunnelTarget{name: "box", host: "box.example.com", repo: "org/repo"}, 22)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(withRepo, "'forward' '--stdio' '22' '--enclave' 'box.example.com' '--repo' 'org/repo'") {
		t.Errorf("proxy command = %q", withRepo)
	}

	host := "otter-4s7ut6c3.box2.tinfoil.sh"
	bare, err := proxyCommand(&rootOptions{}, &tunnelOptions{}, &tunnelTarget{name: host, host: host}, 2022)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(bare, "'forward' '--stdio' '2022' '--enclave' '"+host+"'") {
		t.Errorf("proxy command = %q", bare)
	}
	if strings.Contains(bare, "test-key") {
		t.Error("proxy command carries the API key")
	}
}

func TestResolveTunnelTargetTakesHostnamesWithoutControlplane(t *testing.T) {
	rootOpts := &rootOptions{}
	resolve := func(identifier string) (*tunnelTarget, error) {
		return resolveTunnelTarget(testStreams(), &forwardOptions{}, rootOpts, &trustOptions{}, identifier)
	}

	host := "courageous-otter-cinders-4s7ut6c3.box2.tinfoil.sh"
	target, err := resolve(host)
	if err != nil {
		t.Fatalf("resolveTunnelTarget(%q): %v", host, err)
	}
	if target.host != host || target.repo != "" || target.sshPort != 0 {
		t.Errorf("target = %+v", target)
	}

	rootOpts.repo = "org/repo"
	if target, err = resolve(host); err != nil || target.repo != "org/repo" {
		t.Errorf("--repo not carried onto a hostname target: %+v, %v", target, err)
	}

	rootOpts.repo = ""
	rootOpts.enclaveHost = host
	if target, err = resolve(""); err != nil || target.host != host {
		t.Errorf("--host not used when no target is named: %+v, %v", target, err)
	}

	rootOpts.enclaveHost = ""
	if _, err = resolve(""); err == nil {
		t.Error("resolveTunnelTarget with no target and no --host succeeded")
	}
}

func TestNativeSSHProfilePinsDialHost(t *testing.T) {
	hostKey, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		published    int
		hostOverride string
		portOverride uint
		wantHost     string
		wantPort     int
	}{
		{name: "managed container", published: 11234, wantHost: "debug.tinfoil.sh", wantPort: 11234},
		{name: "managed override", published: 11234, hostOverride: "forwarder.test", portOverride: 2222, wantHost: "forwarder.test", wantPort: 2222},
		{name: "bare hostname", wantHost: "enclave.test", wantPort: 22},
		{name: "bare hostname with port", portOverride: 2222, wantHost: "enclave.test", wantPort: 2222},
		{name: "bare hostname override", hostOverride: "forwarder.test", wantHost: "forwarder.test", wantPort: 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &tunnelTarget{host: "enclave.test", sshPort: tc.published}
			profile := sshProfile{name: "workspace", hostName: nativeSSHHost(target, tc.hostOverride), port: sshTargetPort(target, tc.portOverride), user: "root", hostKey: hostKey}
			if !strings.Contains(profile.render(), fmt.Sprintf("  HostName %s\n  Port %d\n", tc.wantHost, tc.wantPort)) {
				t.Fatalf("profile has wrong SSH endpoint:\n%s", profile.render())
			}
			pinPath := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(pinPath, []byte(profile.pin()), 0600); err != nil {
				t.Fatal(err)
			}
			checkHostKey, err := knownhosts.New(pinPath)
			if err != nil {
				t.Fatal(err)
			}
			remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tc.wantPort}
			if err := checkHostKey(fmt.Sprintf("%s:%d", tc.wantHost, tc.wantPort), remote, hostKey); err != nil {
				t.Fatalf("pin does not match SSH endpoint: %v", err)
			}
			if tc.wantHost != target.host && checkHostKey(fmt.Sprintf("%s:%d", target.host, tc.wantPort), remote, hostKey) == nil {
				t.Fatal("pin matches the attestation hostname instead of only the SSH endpoint")
			}
		})
	}
}

func TestEnclaveAPIKeyIgnoresAdminLoginEnv(t *testing.T) {
	opts := &tunnelOptions{}
	t.Setenv(envAPIKey, "admin_should_not_be_used")
	t.Setenv(envTunnelAPIKey, "")

	if got := enclaveAPIKey(opts); got != "" {
		t.Fatalf("enclaveAPIKey() = %q, want empty when only the admin key env is set", got)
	}

	t.Setenv(envTunnelAPIKey, "tk_from_env")
	if got := enclaveAPIKey(opts); got != "tk_from_env" {
		t.Fatalf("enclaveAPIKey() = %q, want tunnel env value", got)
	}

	opts.tunnelAPIKey = "tk_from_flag"
	if got := enclaveAPIKey(opts); got != "tk_from_flag" {
		t.Fatalf("enclaveAPIKey() = %q, want flag to win over env", got)
	}
}
