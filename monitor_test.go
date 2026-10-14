package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestWorkloadPinsAndTrust(t *testing.T) {
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	for _, repository := range []string{monitorRepo, defaultSandboxRepo} {
		require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte(`{"mode":"frozen","allow":{}}`), 0600))

		row := controlplaneMonitorConfig(testOwnerCredential(t).publicKey())
		row.Repo = repository
		_, err := resolveWorkload(row, repository, "")
		require.ErrorContains(t, err, "mode: frozen")
		target, err := resolveWorkload(row, repository, "tinfoil/containers")
		require.NoError(t, err)
		identity, revision, digest, err := verify.ParseReference(target.source)
		require.NoError(t, err)
		hash := storageHash([]byte(row.Config))
		require.Equal(t, []string{"tinfoil/containers", hash, hash}, []string{identity, revision, digest})
		require.Equal(t, row, target.containerView)
		require.Equal(t, row.Config, target.Config)
		require.NotEmpty(t, target.env[monitorOwnerEnv])

		changed := row
		changed.Config += "# changed without updating reference\n"
		_, err = resolveWorkload(changed, repository, target.source)
		require.ErrorContains(t, err, "digest")
		changed.ConfigName = "/tinfoil/containers/" + storageHash([]byte(changed.Config))
		_, err = resolveWorkload(changed, repository, target.source)
		require.ErrorContains(t, err, "does not match --repo", "an explicit pin must survive sandbox dispatch")
		for _, change := range []func(*containerView){
			func(r *containerView) { r.Config = "" },
			func(r *containerView) { r.Repo = "other/repo" },
			func(r *containerView) { r.Debug = true },
			func(r *containerView) { r.Domain = "host/path" },
		} {
			changed = row
			change(&changed)
			_, err := resolveWorkload(changed, repository, "tinfoil/containers")
			require.Error(t, err)
		}
	}
	for _, env := range []string{"[OWNER]", "[{OWNER: null}]", "[{}]", "[{OWNER: fixed}, {OWNER: changed}]", "[OWNER, {OWNER: fixed}]", "[{OWNER: fixed}, {OTHER: null}]"} {
		_, err := measuredEnvironment("containers:\n  - env: " + env)
		require.Error(t, err, env)
	}
	values, err := measuredEnvironment("containers:\n  - env: [{OWNER: ''}]\n")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"OWNER": ""}, values)
}

func TestManagedCommandsEnforceTrustBeforeCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(dir, "config.json"))
	t.Setenv(envKnownConfigs, filepath.Join(dir, "known-configs.json"))
	require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte(`{"mode":"frozen","allow":{}}`), 0600))
	row := controlplaneMonitorConfig(testOwnerCredential(t).publicKey())
	row.ID = "11111111-1111-4111-8111-111111111111"
	row.Volumes = map[string]string{"workspace": "22222222-2222-4222-8222-222222222222"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		if r.URL.Path == "/api/auth/context" {
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		} else {
			require.Equal(t, "/api/containers/"+row.ID, r.URL.Path)
			json.NewEncoder(w).Encode(row)
		}
	}))
	defer server.Close()
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_test")
	oldRepo, oldDangerous := repo, trustDangerous
	repo, trustDangerous = "", false
	t.Cleanup(func() { repo, trustDangerous = oldRepo, oldDangerous })
	command, _, err := rootCmd.Find([]string{"monitor", "open"})
	require.NoError(t, err)
	require.ErrorContains(t, command.RunE(command, []string{row.ID}), "mode: frozen")
	row.Repo = defaultSandboxRepo
	require.ErrorContains(t, sandboxEnrollCmd.RunE(sandboxEnrollCmd, []string{row.ID}), "mode: frozen")
	require.ErrorContains(t, attestSSHCmd.RunE(attestSSHCmd, []string{row.ID}), "mode: frozen")
	repo = "tinfoil/containers@" + strings.Repeat("0", 64)
	require.ErrorContains(t, attestSSHCmd.RunE(attestSSHCmd, []string{row.ID}), "does not match --repo")
	repo = "tinfoil/containers"
	target, err := resolveTunnelTarget(row.ID)
	require.NoError(t, err)
	require.Same(t, target.container, &target.workload.containerView)
	require.Equal(t, target.repo, target.workload.source)
	// Even an approved config cannot send credentials without the network binding.
	_, err = connectSandbox(target.workload)
	require.ErrorContains(t, err, "measured instance and Monitor bindings")
	require.NoDirExists(t, filepath.Join(dir, "resources"))
	require.NoDirExists(t, filepath.Join(dir, "monitors"))
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
