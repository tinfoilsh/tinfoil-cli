package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestInteractiveInstallDemo(t *testing.T) {
	if os.Getenv("ATTEST_SSH_DEMO") == "" {
		t.Skip("set ATTEST_SSH_DEMO=1 to exercise the install prompt")
	}
	home := os.Getenv("ATTEST_SSH_DEMO_HOME")
	if home == "" {
		home = t.TempDir()
	}
	profile := sshProfile{name: "demo-enclave", hostName: "enclave.example.com", port: 22, user: "root", hostKey: testHostKey(t)}
	t.Logf("Installing into %s", home)
	fmt.Fprintln(os.Stderr, "Attestation successful.")
	if err := profile.installTo(home, os.Stdin, os.Stderr, true, false); err != nil {
		t.Fatal(err)
	}
}

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestHasTopLevelInclude(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"first line", "Include tinfoil/*.conf\n\nHost other\n", true},
		{"after comment", "# comment\nInclude tinfoil/*.conf\n", true},
		{"after host", "Host other\nInclude tinfoil/*.conf\n", false},
		{"wrong glob", "Include other/*.conf\n", false},
		{"commented", "# Include tinfoil/*.conf\nHost other\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasTopLevelInclude([]byte(tc.in)); got != tc.want {
				t.Fatalf("hasTopLevelInclude(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestInstallToAddsProfileAndPromptsInclude(t *testing.T) {
	home := t.TempDir()
	profile := sshProfile{name: "my-container", hostName: "enclave.example.com", port: 22, user: "root", hostKey: testHostKey(t)}

	var out bytes.Buffer
	if err := profile.installTo(home, strings.NewReader("y\n"), &out, true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Added SSH profile my-container") {
		t.Fatalf("added message missing: %s", out.String())
	}
	if !strings.Contains(out.String(), "Added Include tinfoil/*.conf") {
		t.Fatalf("include message missing: %s", out.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(out.String()), "Connect with: ssh my-container") {
		t.Fatalf("connect should be last: %s", out.String())
	}

	conf, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(conf, []byte("Include tinfoil/*.conf\n")) {
		t.Fatalf("config = %q", conf)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "tinfoil", "my-container.conf")); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if err := profile.installTo(home, strings.NewReader(""), &out, true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Updated SSH profile my-container") {
		t.Fatalf("updated message missing: %s", out.String())
	}
	if strings.Contains(out.String(), "Add it now") {
		t.Fatalf("prompted again after include exists: %s", out.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(out.String()), "Connect with: ssh my-container") {
		t.Fatalf("connect should be last: %s", out.String())
	}
}

func TestInstallToDeclinedIncludeLeavesConfig(t *testing.T) {
	home := t.TempDir()
	profile := sshProfile{name: "my-container", hostName: "enclave.example.com", port: 22, user: "root", hostKey: testHostKey(t)}

	var out bytes.Buffer
	if err := profile.installTo(home, strings.NewReader("n\n"), &out, true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Note: For your SSH client to use this profile") {
		t.Fatalf("help missing: %s", out.String())
	}
	if strings.Contains(out.String(), "Then connect with") {
		t.Fatalf("stale connect line in help: %s", out.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(out.String()), "Connect with: ssh my-container") {
		t.Fatalf("connect should be last: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "config")); !os.IsNotExist(err) {
		t.Fatalf("config should not be created, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "tinfoil", "my-container.conf")); err != nil {
		t.Fatal(err)
	}
}

func TestInstallToNonInteractiveDoesNotWriteConfig(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	existing := []byte("Host other\n  HostName example.com\n")
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), existing, 0o600); err != nil {
		t.Fatal(err)
	}
	profile := sshProfile{name: "my-container", hostName: "enclave.example.com", port: 22, user: "root", hostKey: testHostKey(t)}

	var out bytes.Buffer
	if err := profile.installTo(home, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatalf("config changed without consent: %q", got)
	}
	if !strings.Contains(out.String(), "Note: For your SSH client to use this profile") {
		t.Fatalf("help missing: %s", out.String())
	}
}

func TestInstallToYesFlagWritesInclude(t *testing.T) {
	home := t.TempDir()
	profile := sshProfile{name: "my-container", hostName: "enclave.example.com", port: 22, user: "root", hostKey: testHostKey(t)}

	var out bytes.Buffer
	if err := profile.installTo(home, strings.NewReader(""), &out, false, true); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(conf, []byte("Include tinfoil/*.conf\n")) {
		t.Fatalf("config = %q", conf)
	}
}
