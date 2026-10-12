package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
)

func controlplaneMonitorConfig(publicKey string) containerView {
	config := fmt.Sprintf("containers:\n  - name: monitor\n    env:\n      - MONITOR_OWNER_PUBLIC_KEY: %q\n    command: [-production]\n", publicKey)
	return containerView{ID: "container-1", Name: "personal", Status: statusRunning, Domain: "personal.user-1.users.monitors.tinfoil.dev", Config: config, ConfigName: "/tinfoil/containers/" + storageHash([]byte(config)), Repo: monitorRepo, CurrentTag: "v1.2.3"}
}

func TestWorkloadSourcePinsControlplaneConfig(t *testing.T) {
	for _, repository := range []string{monitorRepo, defaultSandboxRepo} {
		t.Run(repository, func(t *testing.T) {
			row := controlplaneMonitorConfig(testOwnerCredential(t).publicKey())
			row.Repo = repository
			source, err := workloadSource(row, repository)
			require.NoError(t, err)
			identity, revision, pinned, err := verify.ParseReference(source)
			require.NoError(t, err)
			hash := storageHash([]byte(row.Config))
			require.Equal(t, []string{"tinfoil/containers", hash, hash}, []string{identity, revision, pinned})
			_, err = newVerifiedClient(row.Domain, source, "")
			require.NoError(t, err)

			for _, change := range []func(*containerView){
				func(r *containerView) { r.Config += "# changed without updating reference\n" },
				func(r *containerView) { r.Config = "" },
				func(r *containerView) { r.ConfigName = "" },
				func(r *containerView) { r.Repo = "other/repo" },
				func(r *containerView) { r.Debug = true },
				func(r *containerView) { r.Domain = "host/path" },
			} {
				changed := row
				change(&changed)
				_, err := workloadSource(changed, repository)
				require.Error(t, err)
			}
			row.Config += "# new controlplane configuration\n"
			row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
			updated, err := workloadSource(row, repository)
			require.NoError(t, err)
			require.NotEqual(t, source, updated, "attestation must check the new config digest")
		})
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
	credential, err := newSigningCredential()
	require.NoError(t, err)
	binary := filepath.Join(t.TempDir(), "monitor")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir, build.Env = source, append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building Monitor: %v\n%s", err, output)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(hostPrivate, "")
	require.NoError(t, err)
	hostKeyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0o600))
	bucket, api, sshAddress := t.TempDir(), freeAddress(t), freeAddress(t)
	start := func() *exec.Cmd {
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
		return cmd
	}
	process := start()
	dir := t.TempDir()
	require.NoError(t, saveMonitorGeneration(dir, 0))
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/owner/challenge", "/unlock", "/app/"} {
		response, err := client.Get("http://" + api + path)
		require.NoError(t, err)
		response.Body.Close()
		require.Equal(t, http.StatusNotFound, response.StatusCode)
	}
	hostKey, err := ssh.NewPublicKey(hostPrivate.Public())
	require.NoError(t, err)
	conn, err := net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	_, err = connectOwnerSSH(conn, "localhost", hostKey, testOwnerCredential(t).SigningSeed)
	require.Error(t, err, "another key cannot enter a locked Monitor")
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	panel, err := connectOwnerSSH(conn, "localhost", hostKey, credential.SigningSeed)
	require.NoError(t, err, "the measured owner can enter while locked")
	defer panel.Close()
	require.Error(t, monitorOwnerRequest(panel, dir, "GET", "/policy", nil, nil))
	require.Error(t, monitorOwnerRequest(panel, dir, "POST", "/unlock", map[string]any{"storage_key": credential.Key}, nil), "unlock cannot initialize an empty store")
	require.NoError(t, unlockMonitor(panel, dir, credential))
	require.Error(t, unlockMonitor(panel, dir, testOwnerCredential(t)), "wrong storage key refused")
	testOwnerSSHPanel(t, panel, dir, credential.SigningSeed, hostKey, sshAddress)
	device, agent := testSandboxPairing(t, panel, dir, hostKey, sshAddress)
	// A new process must unlock using the saved floor and recover the encrypted state.
	require.NoError(t, process.Process.Kill())
	process.Wait()
	// A new VM boot rotates the public host key, independently of the sealed state.
	_, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err = ssh.MarshalPrivateKey(nextPrivate, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0600))
	start()
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	_, err = connectOwnerSSH(conn, "localhost", hostKey, credential.SigningSeed)
	require.Error(t, err, "the prior boot pin cannot authorize this boot")
	hostKey, err = ssh.NewPublicKey(nextPrivate.Public())
	require.NoError(t, err)
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	recovered, err := connectOwnerSSH(conn, "localhost", hostKey, credential.SigningSeed)
	require.NoError(t, err)
	defer recovered.Close()
	require.NoError(t, unlockMonitor(recovered, dir, credential))
	require.ErrorContains(t, pairSandboxMonitor(recovered, dir, "work", device, agent), "identity was revoked")
	_, err = updateProfile(dir, func(p *monitorProfile) error { p.Generation += 5; return nil })
	require.NoError(t, err)
	require.ErrorContains(t, unlockMonitor(recovered, dir, credential), "older than")
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

func TestWorkloadRejectsUnmeasuredEnvironment(t *testing.T) {
	for _, env := range []string{"[OWNER]", "[MONITOR_ENDPOINT]", "[{OWNER: null}]", "[{}]", "[{OWNER: fixed}, {OTHER: null}]"} {
		row := controlplaneMonitorConfig("test")
		row.Config = "containers:\n  - name: monitor\n    env: " + env + "\n"
		row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
		_, err := workloadSource(row, monitorRepo)
		require.Error(t, err, env)
	}
	row := controlplaneMonitorConfig("")
	_, err := workloadSource(row, monitorRepo)
	require.NoError(t, err, "a literal empty string cannot import runtime env")
}

func TestOnlySandboxLocatorMayBeUnmeasured(t *testing.T) {
	_, err := measuredEnvironment("containers:\n  - env: [MONITOR_ENDPOINT, {OWNER: fixed}]\n", true)
	require.NoError(t, err)
	for _, env := range []string{"[MONITOR_ENDPOINT, MONITOR_ENDPOINT]", "[{MONITOR_ENDPOINT: fixed}]", "[MONITOR_ENDPOINT, OWNER]"} {
		_, err := measuredEnvironment("containers:\n  - env: "+env, true)
		require.Error(t, err)
	}
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
