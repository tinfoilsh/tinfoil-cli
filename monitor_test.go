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

func TestMonitorProvisioningPublishesOnlyPublicKeyAndReusesSavedKeys(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	previousURL, previousTag, previousHost := workloadReleaseURL, monitorTag, monitorHost
	monitorTag = ""
	monitorHost = "control.box2.tinfoil.sh"
	t.Cleanup(func() { workloadReleaseURL, monitorTag, monitorHost = previousURL, previousTag, previousHost })
	var row containerView
	creates, releaseLookups := 0, 0
	latestTag, expectedTag := "v9.8.7", "v9.8.7"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /" + monitorRepo + "/releases/latest":
			require.Empty(t, r.Header.Get("Authorization"), "controlplane credentials stay out of release discovery")
			releaseLookups++
			json.NewEncoder(w).Encode(map[string]string{"tag_name": latestTag})
		case "GET /api/containers":
			rows := []containerView{}
			if row.ID != "" {
				rows = append(rows, row)
			}
			json.NewEncoder(w).Encode(rows)
		case "POST /api/containers":
			var body struct {
				Name          string            `json:"name"`
				Repo          string            `json:"repo"`
				Tag           string            `json:"tag"`
				HostName      string            `json:"host_name"`
				Variables     map[string]string `json:"variables"`
				ObjectStorage map[string]string `json:"object_storage"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			require.NoError(t, decoder.Decode(&body))
			require.Equal(t, monitorRepo, body.Repo)
			require.NotNil(t, body.ObjectStorage)
			require.Empty(t, body.ObjectStorage)
			require.Len(t, body.Variables, 1)
			require.Equal(t, expectedTag, body.Tag)
			require.Equal(t, "control.box2.tinfoil.sh", body.HostName)
			row = controlplaneMonitorConfig(body.Variables[monitorOwnerEnv])
			row.Name, row.CurrentTag = body.Name, body.Tag
			row.HostName = body.HostName
			creates++
			json.NewEncoder(w).Encode(row)
		case "GET /api/containers/container-1":
			json.NewEncoder(w).Encode(row)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	workloadReleaseURL = server.URL + "/%s/releases/latest"
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "admin_test"})
	scope := accountScope{ControlplaneURL: server.URL, UserID: "user_1"}
	create := func() error { return provisionMonitor(client, scope, "personal") }
	require.NoError(t, create())
	dir, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	owner, err := readOwnerCredential(filepath.Join(dir, monitorOwnerKeyName))
	require.NoError(t, err)
	require.Contains(t, row.Config, owner.publicKey())
	latestTag = "v10.0.0"
	require.NoError(t, create(), "a retry uses the saved key")
	require.Equal(t, 1, creates)
	require.Equal(t, "v9.8.7", row.CurrentTag, "a retry keeps the deployed release")
	require.Equal(t, 1, releaseLookups, "existing Monitors need no release lookup")
	originalConfig := row.Config
	row.Config = strings.Replace(row.Config, owner.publicKey(), testOwnerCredential(t).publicKey(), 1)
	row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
	require.ErrorContains(t, create(), "owner public key does not match")
	row.Config = originalConfig
	row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
	monitorHost = "other-host"
	require.ErrorContains(t, create(), "already uses host control.box2.tinfoil.sh")
	monitorHost = "control.box2.tinfoil.sh"
	row.CurrentTag = "next-release"
	row.Config += "# updated through the controlplane\n"
	require.ErrorContains(t, create(), "config reference does not match")
	row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
	require.NoError(t, create(), "the CLI accepts updated controlplane config for attestation")
	again, err := readOwnerCredential(filepath.Join(dir, monitorOwnerKeyName))
	require.NoError(t, err)
	require.True(t, sameOwnerCredential(owner, again))
	row.Domain = "other.user-1.users.monitors.tinfoil.dev"
	require.ErrorContains(t, create(), "no longer matches the domain")
	row.ID = ""
	require.ErrorContains(t, create(), "use a new name")
	require.Equal(t, 1, creates)
	monitorTag, expectedTag = "v10.1.0-preview.1", "v10.1.0-preview.1"
	lookups := releaseLookups
	require.NoError(t, provisionMonitor(client, scope, "explicit"))
	require.Equal(t, 2, creates)
	require.Equal(t, lookups, releaseLookups, "--tag bypasses latest-release discovery")
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
	require.NoError(t, unlockMonitor(panel, dir, credential))
	require.Error(t, unlockMonitor(panel, dir, testOwnerCredential(t)), "wrong storage key refused")
	testOwnerSSHPanel(t, panel, dir, credential.SigningSeed, hostKey, sshAddress)
	testSandboxPairing(t, panel, dir, hostKey, sshAddress)
	// A new process must unlock using the saved floor and recover the encrypted state.
	require.NoError(t, process.Process.Kill())
	process.Wait()
	start()
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	recovered, err := connectOwnerSSH(conn, "localhost", hostKey, credential.SigningSeed)
	require.NoError(t, err)
	defer recovered.Close()
	require.NoError(t, unlockMonitor(recovered, dir, credential))
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
	for _, env := range []string{"[OWNER]", "[{OWNER: null}]", "[{}]", "[{OWNER: fixed}, {OTHER: null}]"} {
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
