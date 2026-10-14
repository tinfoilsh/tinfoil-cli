package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestManagedTrustPrecedesCredentials(t *testing.T) {
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	for _, kind := range []string{"sandbox", "monitor"} {
		require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte(`{"mode":"frozen","allow":{}}`), 0600))

		row := containerView{Repo: managedRepo(kind), Domain: "work.example", Config: "containers: [{env: [{OWNER: owner}]}]"}
		row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
		_, err := resolveWorkload(row, row.Repo, "")
		require.ErrorContains(t, err, "mode: frozen")
		target, err := resolveWorkload(row, row.Repo, "tinfoil/containers")
		require.NoError(t, err)
		row.Config += "\n# changed"
		_, err = resolveWorkload(row, row.Repo, target.source)
		require.ErrorContains(t, err, "digest")
		row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
		_, err = resolveWorkload(row, row.Repo, target.source)
		require.ErrorContains(t, err, "does not match --repo")
	}
	for _, env := range []string{"[OWNER]", "[{OWNER: null}]", "[{}]", "[{OWNER: a}, {OWNER: b}]"} {
		_, err := measuredEnvironment("containers: [{env: " + env + "}]")
		require.Error(t, err)
	}
}

func TestMonitorUnlockAndSSHPanelAgainstRealMonitor(t *testing.T) {
	source := os.Getenv("TINFOIL_MONITOR_TEST_SOURCE")
	if source == "" {
		source = filepath.Join("..", "monitor")
	}
	source, err := filepath.Abs(source)
	require.NoError(t, err)
	if _, err := os.Stat(filepath.Join(source, "routes.go")); err != nil {
		t.Skip("no Monitor checkout with routes next to tinfoil-cli")
	}
	credential := testOwnerCredential(t)
	binary := filepath.Join(t.TempDir(), "monitor")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir, build.Env = source, append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building Monitor: %v\n%s", err, output)
	}
	hostKeyPath := filepath.Join(t.TempDir(), "host_key")
	hostSigner, err := ensureSSHIdentity(hostKeyPath, nil)
	require.NoError(t, err)
	hostKey := hostSigner.PublicKey()
	bucket, api, sshAddress := t.TempDir(), freeAddress(t), freeAddress(t)
	cmd := exec.Command(binary, "-production", "-ssh-host-key", hostKeyPath,
		"-bucket", "file://"+bucket+"?no_tmp_dir=1", "-api", api, "-listen", sshAddress)
	cmd.Env = append(os.Environ(), "MONITOR_OWNER_PUBLIC_KEY="+credential.publicKey())
	var logs bytes.Buffer
	cmd.Stderr = &logs
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + api + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)
	dir := t.TempDir()
	require.NoError(t, saveMonitorGeneration(dir, 0))
	conn, err := net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	_, err = connectOwnerSSH(conn, "localhost", hostKey, testOwnerCredential(t).SigningSeed)
	require.Error(t, err, "another key cannot enter a locked Monitor")
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	panel, err := connectOwnerSSH(conn, "localhost", hostKey, credential.SigningSeed)
	require.NoError(t, err, "the measured owner can enter while locked")
	defer panel.Close()
	require.Error(t, monitorOwnerRequest(panel, dir, "GET", "/policy", nil))
	require.Error(t, monitorOwnerRequest(panel, dir, "POST", "/unlock", map[string]any{"storage_key": credential.Key}), "unlock cannot initialize an empty store")
	require.NoError(t, unlockMonitor(panel, dir, credential))
	require.Error(t, unlockMonitor(panel, dir, testOwnerCredential(t)), "wrong storage key refused")
	device, agent := authorizedLine(testSigner(t)), authorizedLine(testSigner(t))
	require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
	require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
	identity := filepath.Join(dir, "owner")
	require.NoError(t, ensureOwnerSSHKey(identity, credential.SigningSeed))
	host, port, err := net.SplitHostPort(sshAddress)
	require.NoError(t, err)
	number, err := strconv.Atoi(port)
	require.NoError(t, err)
	profile := sshProfile{name: "personal", hostName: host, port: number, user: "owner", identityFile: identity, hostKey: hostKey, hostKeyAlias: "monitor.example"}
	config, pins := filepath.Join(dir, "config"), filepath.Join(dir, "pins")
	require.NoError(t, os.WriteFile(config, []byte(profile.render()), 0600))
	for index, key := range []ssh.PublicKey{hostKey, testHostKey(t)} {
		profile.hostKey = key
		require.NoError(t, os.WriteFile(pins, []byte(profile.pin()), 0600))
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		output, err := exec.CommandContext(ctx, "ssh", "-F", config, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile="+pins, "personal", "true").CombinedOutput()
		cancel()
		require.Error(t, err, "Monitor refuses interactive sessions")
		require.Equal(t, index != 0, strings.Contains(string(output), "Host key verification failed"), string(output))
		if index == 0 {
			require.Contains(t, string(output), "open failed")
		}
	}
	_, err = updateProfile(dir, func(p *monitorProfile) error { p.Generation += 5; return nil })
	require.NoError(t, err)
	require.ErrorContains(t, unlockMonitor(panel, dir, credential), "older than")
}

func freeAddress(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().String()
}

func testSigner(t *testing.T) ssh.Signer {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return signer
}

func authorizedLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func connectOwnerSSH(conn net.Conn, host string, hostKey ssh.PublicKey, seed []byte) (*ssh.Client, error) {
	return connectOwnerSSHAs(conn, host, hostKey, seed, "owner")
}

func connectOwnerSSHAs(conn net.Conn, host string, hostKey ssh.PublicKey, seed []byte, user string) (*ssh.Client, error) {
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, err
	}
	return connectOwnerSigner(conn, host, hostKey, signer, user)
}
