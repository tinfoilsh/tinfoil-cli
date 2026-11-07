package owner

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestMonitorSessionAgainstRealMonitor(t *testing.T) {
	source := os.Getenv("TINFOIL_MONITOR_TEST_SOURCE")
	if source == "" {
		source = filepath.Join("..", "..", "..", "confidential-agent-monitor")
	}
	if _, err := os.Stat(filepath.Join(source, "internal", "tinfoil", "ownerauth")); err != nil {
		t.Skip("no Monitor checkout next to tinfoil-cli")
	}
	binary := filepath.Join(t.TempDir(), "monitor")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir, build.Env = source, append(os.Environ(), "GOWORK=off")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	keys := &keyStateServer{}
	cpServer := httptest.NewServer(keys)
	defer cpServer.Close()
	cp, scope, dek := testLogin(t, cpServer, keys)
	mk, err := newMKSession(cp, scope)
	require.NoError(t, err)
	saved := newResourceKey("monitor")
	_, err = mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, saved) })
	require.NoError(t, err)
	minimum := func() uint64 {
		return *findKey(keys.payload(t, dek, mk.context), func(r *mkResource) bool { return r.KeyID == saved.KeyID }).MinGeneration
	}
	hostKeyPath := filepath.Join(t.TempDir(), "host_key")
	hostSigner, err := ensureSSHIdentity(hostKeyPath, nil)
	require.NoError(t, err)
	hostKey := hostSigner.PublicKey()
	bucket, api, sshAddress := t.TempDir(), freeAddress(t), freeAddress(t)
	ownerSessionKey := monitorOwnerSessionKey(t)
	start := func() func() {
		cmd := exec.Command(binary, "-production", "-ssh-host-key", hostKeyPath, "-owner-session-key", ownerSessionKey, "-bucket", "file://"+bucket+"?no_tmp_dir=1", "-api", api, "-listen", sshAddress)
		cmd.Env = append(os.Environ(), "MONITOR_OWNER_PUBLIC_KEY="+saved.OwnerPublicKey)
		var logs bytes.Buffer
		cmd.Stderr = &logs
		require.NoError(t, cmd.Start())
		var stopped sync.Once
		stop := func() {
			stopped.Do(func() {
				cmd.Process.Kill()
				cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			})
		}
		t.Cleanup(stop)
		require.Eventually(t, func() bool {
			conn, err := net.Dial("tcp", sshAddress)
			if err == nil {
				conn.Close()
			}
			return err == nil
		}, 10*time.Second, 50*time.Millisecond)
		return stop
	}
	stop := start()
	connect := func(seed, storage []byte, dir string) (*Monitor, error) {
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
		require.NoError(t, err)
		client, err := Connect(conn, "localhost", hostKey, signer, "owner")
		if err != nil {
			return nil, err
		}
		// A clean client opens with the minimum generation recovered from the key bundle.
		_, err = UpdateProfile(dir, func(p *Profile) error { p.Generation = max(p.Generation, minimum()); return nil })
		require.NoError(t, err)
		_, err = ensureSSHKey(filepath.Join(dir, MonitorDeviceKeyName))
		require.NoError(t, err)
		m := &Monitor{service: cp.service, client: client, dir: dir, domain: "localhost", address: sshAddress, hostKey: hostKey,
			keys: &resourceKeys{service: cp.service, mode: "tmk", signer: signer, storageKey: bytes.Clone(storage), mk: mk, keyID: saved.KeyID, minGeneration: minimum()}}
		m.request = func(method, path string, input, out any) error {
			return monitorOwnerRequest(client, dir, method, path, input, out)
		}
		return m, nil
	}
	_, err = connect(testSeed(t), saved.StorageKey, t.TempDir())
	require.Error(t, err, "another key cannot enter a locked Monitor")
	dir := t.TempDir()
	m, err := connect(saved.OwnerSeed, saved.StorageKey, dir)
	require.NoError(t, err, "the measured owner can enter while locked")
	defer m.close()
	var health struct {
		Locked bool   `json:"locked"`
		State  string `json:"state"`
	}
	require.NoError(t, m.request(http.MethodGet, "/healthz", nil, &health))
	require.Equal(t, "absent", health.State)
	require.Error(t, m.request(http.MethodGet, "/policy", nil, nil))
	require.ErrorContains(t, m.request(http.MethodPost, "/unlock", map[string]any{"storage_key": saved.StorageKey, "initialize": true}, nil), "initialize", "clients cannot direct initialization")
	require.NoError(t, m.open(t.Context(), "monitor", saved.OwnerPublicKey, mkBinding{}, true))
	require.NoError(t, m.request(http.MethodGet, "/healthz", nil, &health))
	require.Equal(t, "present", health.State)
	other, err := connect(saved.OwnerSeed, saved.StorageKey, t.TempDir())
	require.NoError(t, err)
	other.keys.storageKey = testSeed(t)
	require.Error(t, other.unlock(false), "a wrong storage key is refused")
	other.client.Close()
	reported := m.view.HostKey
	m.view.HostKey = authorizedLine(testSigner(t))
	m.hostKey, hostKey = testSigner(t).PublicKey(), m.hostKey
	require.ErrorContains(t, m.unlock(false), "attested")
	m.hostKey = hostKey
	require.NoError(t, m.unlock(false))
	require.Equal(t, reported, m.view.HostKey)
	agent := authorizedLine(testSigner(t))
	require.False(t, m.authorizes(agent))
	require.NoError(t, m.enrollAgent(t.Context(), "sandbox-work", agent))
	require.True(t, m.authorizes(agent))
	var profile Profile
	require.NoError(t, readStorageJSON(filepath.Join(dir, ProfileFile), &profile))
	require.Positive(t, profile.Generation)
	require.Equal(t, profile.Generation, minimum(), "the observed generation is checkpointed into the key bundle")
	// Keep a valid older Monitor object, copied while the Monitor is stopped.
	stop()
	snapshot := t.TempDir()
	require.NoError(t, os.CopyFS(snapshot, os.DirFS(bucket)))
	stop = start()
	m, err = connect(saved.OwnerSeed, saved.StorageKey, dir)
	require.NoError(t, err)
	defer m.close()
	require.NoError(t, m.unlock(true))
	require.True(t, m.authorizes(agent), "a restarted Monitor keeps its enrolled identities")
	// Exercise a sandbox reverse route through the real Monitor SSH server.
	publisherSigner := testSigner(t)
	conn, err := net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	publisher, err := Connect(conn, "localhost", hostKey, publisherSigner, "sandbox-v2:22222222-2222-4222-8222-222222222222")
	require.NoError(t, err)
	defer publisher.Close()
	route, err := publisher.Listen("tcp", "127.0.0.1:22")
	require.NoError(t, err)
	defer route.Close()
	go func() {
		for {
			conn, err := route.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	device, err := loadSigner(filepath.Join(dir, MonitorDeviceKeyName))
	require.NoError(t, err)
	checkRoute := func(allowed bool) {
		t.Helper()
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		client, err := Connect(conn, "localhost", hostKey, device, MonitorSSHUser)
		require.NoError(t, err)
		defer client.Close()
		routed, err := client.DialContext(t.Context(), "tcp", net.JoinHostPort(routeName(publisherSigner.PublicKey()), "22"))
		if !allowed {
			var channel *ssh.OpenChannelError
			require.ErrorAs(t, err, &channel)
			require.Equal(t, ssh.Prohibited, channel.Reason)
			return
		}
		require.NoError(t, err)
		defer routed.Close()
		timer := time.AfterFunc(5*time.Second, func() { client.Close() })
		defer timer.Stop()
		_, err = io.WriteString(routed, "sandbox reachable")
		require.NoError(t, err)
		reply := make([]byte, len("sandbox reachable"))
		_, err = io.ReadFull(routed, reply)
		require.NoError(t, err)
		require.Equal(t, "sandbox reachable", string(reply))
	}
	checkRoute(true)
	name := "device-" + hash([]byte(authorizedLine(device)))[:16]
	require.NoError(t, m.request(http.MethodPost, "/policy/edits", map[string]any{"changes": []any{map[string]any{"path": []string{"identities", name, "routes"}, "value": false}}}, nil))
	checkRoute(false)
	require.NoError(t, m.unlock(true), "an explicit owner open restores this device")
	checkRoute(true)
	// A removed sandbox identity stays removed: re-enrollment is refused, including after a Monitor-only restart.
	require.NoError(t, m.request(http.MethodPost, "/policy/edits", map[string]any{"changes": []any{map[string]any{"path": []string{"identities", "sandbox-work"}, "delete": true}}}, nil))
	require.NoError(t, m.unlock(false))
	require.False(t, m.authorizes(agent))
	require.ErrorContains(t, m.enrollAgent(t.Context(), "sandbox-work", agent), "revoked")
	m.checkpoint(t.Context())
	require.Greater(t, minimum(), profile.Generation)
	// Monitor-only restart: a clean client recovers the minimum from the key bundle and reopens saved state.
	stop()
	stop = start()
	restarted, err := connect(saved.OwnerSeed, saved.StorageKey, t.TempDir())
	require.NoError(t, err)
	require.NoError(t, restarted.unlock(false))
	require.False(t, restarted.authorizes(agent), "reconnecting never restores a removed identity")
	restarted.close()
	// A valid but older Monitor object is refused by a clean client that recovered the newer minimum.
	stop()
	require.NoError(t, os.RemoveAll(bucket))
	require.NoError(t, os.CopyFS(bucket, os.DirFS(snapshot)))
	stop = start()
	rolledBack, err := connect(saved.OwnerSeed, saved.StorageKey, t.TempDir())
	require.NoError(t, err)
	defer rolledBack.close()
	require.ErrorContains(t, rolledBack.unlock(false), "older than")
}

func TestMonitorUnlockMissingDeviceKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeStorageJSON(filepath.Join(dir, ProfileFile), Profile{Generation: 1}, false))
	m := &Monitor{dir: dir, keys: &resourceKeys{storageKey: testSeed(t)}}
	err := m.unlock(true)
	require.ErrorContains(t, err, "restore Perimeter device key")
	require.ErrorContains(t, err, filepath.Join(dir, MonitorDeviceKeyName))
	require.NoFileExists(t, filepath.Join(dir, MonitorDeviceKeyName), "restoration must not replace a lost key")
}

func freeAddress(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().String()
}

func monitorOwnerSessionKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "owner-session.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}
