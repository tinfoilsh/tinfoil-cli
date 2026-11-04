package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestManagedTrustPrecedesCredentials(t *testing.T) {
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	for _, test := range []struct{ kind, prefix string }{
		{"sandbox", "/tinfoil/containers"},
		{"monitor", "/tinfoil/containers"},
		{"monitor", "/acme/confidential-agent-monitor"},
		{"sandbox", "/user-9c4a7f21-e0b8-36d5-6a13-c8fe42d907ab/confidential-agent-sandbox"},
	} {
		require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte(`{"mode":"frozen","allow":{}}`), 0600))

		row := containerView{Repo: managedRepo(test.kind), Domain: "work.example", Config: "containers: [{env: [{OWNER: owner}]}]"}
		row.ConfigName = test.prefix + "/" + storageHash([]byte(row.Config))
		_, err := resolveWorkload(row, row.Repo, "")
		require.ErrorContains(t, err, "mode: frozen")
		target, err := resolveWorkload(row, row.Repo, strings.TrimPrefix(test.prefix, "/"))
		require.NoError(t, err)
		row.Config += "\n# changed"
		_, err = resolveWorkload(row, row.Repo, target.source)
		require.ErrorContains(t, err, "digest")
		row.ConfigName = test.prefix + "/" + storageHash([]byte(row.Config))
		_, err = resolveWorkload(row, row.Repo, target.source)
		require.ErrorContains(t, err, "does not match --repo")
	}
	for _, env := range []string{"[OWNER]", "[{OWNER: null}]", "[{}]", "[{OWNER: a}, {OWNER: b}]"} {
		_, err := measuredEnvironment("containers: [{env: " + env + "}]")
		require.Error(t, err)
	}
}

func TestMonitorSessionAgainstRealMonitor(t *testing.T) {
	source := os.Getenv("TINFOIL_MONITOR_TEST_SOURCE")
	if source == "" {
		source = filepath.Join("..", "confidential-agent-monitor")
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
	start := func() func() {
		cmd := exec.Command(binary, "-production", "-ssh-host-key", hostKeyPath,
			"-bucket", "file://"+bucket+"?no_tmp_dir=1", "-api", api, "-listen", sshAddress)
		cmd.Env = append(os.Environ(), "MONITOR_OWNER_PUBLIC_KEY="+saved.OwnerPublicKey)
		var logs bytes.Buffer
		cmd.Stderr = &logs
		require.NoError(t, cmd.Start())
		stop := func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				t.Log(logs.String())
			}
		}
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
	t.Cleanup(func() { stop() })
	connect := func(seed, storage []byte, dir string) (*monitorSession, error) {
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
		require.NoError(t, err)
		client, err := connectOwnerSigner(conn, "localhost", hostKey, signer, "owner")
		if err != nil {
			return nil, err
		}
		// A clean client opens with the minimum generation recovered from the key bundle.
		_, err = updateProfile(dir, func(p *monitorProfile) error { p.Generation = max(p.Generation, minimum()); return nil })
		require.NoError(t, err)
		_, err = ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
		require.NoError(t, err)
		m := &monitorSession{client: client, dir: dir, domain: "localhost", address: sshAddress, hostKey: hostKey,
			keys: &resourceKeys{mode: "tmk", signer: signer, storageKey: bytes.Clone(storage), mk: mk, keyID: saved.KeyID, minGeneration: minimum()}}
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

	agentSigner := testSigner(t)
	agent := authorizedLine(agentSigner)
	require.False(t, m.authorizes(agent))
	require.NoError(t, m.enrollAgent(t.Context(), "sandbox-work", agent))
	require.True(t, m.authorizes(agent))
	var profile monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile))
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
	publisher, err := connectOwnerSigner(conn, "localhost", hostKey, publisherSigner, "sandbox-v2:22222222-2222-4222-8222-222222222222")
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
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	device, err := loadSigner(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	checkRoute := func(allowed bool) {
		t.Helper()
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		client, err := connectOwnerSigner(conn, "localhost", hostKey, device, monitorSSHUser)
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
	name := "device-" + storageHash([]byte(authorizedLine(device)))[:16]
	require.NoError(t, m.request(http.MethodPost, "/policy/edits", map[string]any{"changes": []any{map[string]any{"path": []string{"identities", name, "routes"}, "value": false}}}, nil))
	checkRoute(false)
	require.NoError(t, m.unlock(true), "an explicit owner open restores this device")
	checkRoute(true)
	nativeSandboxTransport(t, sshAddress, hostKey, dir)

	// A removed sandbox identity stays removed: re-enrollment is refused, including after a Monitor-only restart.
	require.NoError(t, m.request(http.MethodPost, "/policy/edits", map[string]any{
		"changes": []any{map[string]any{"path": []string{"identities", "sandbox-work"}, "delete": true}},
	}, nil))
	require.NoError(t, m.unlock(false))
	require.False(t, m.authorizes(agent))
	require.ErrorContains(t, m.enrollAgent(t.Context(), "sandbox-work", agent), "revoked")
	m.checkpoint(t.Context())
	removedAt := minimum()
	require.Greater(t, removedAt, profile.Generation)

	identity := filepath.Join(dir, "owner")
	require.NoError(t, ensureOwnerSSHKey(identity, saved.OwnerSeed))
	host, port, err := net.SplitHostPort(sshAddress)
	require.NoError(t, err)
	number, err := strconv.Atoi(port)
	require.NoError(t, err)
	sshProfileUnderTest := sshProfile{name: "personal", hostName: host, port: number, user: "owner", identityFile: identity, hostKey: hostKey, hostKeyAlias: "monitor.example"}
	config, pins := filepath.Join(dir, "config"), filepath.Join(dir, "pins")
	require.NoError(t, os.WriteFile(config, []byte(sshProfileUnderTest.render()), 0600))
	if _, err := exec.LookPath("ssh"); err == nil {
		for index, key := range []ssh.PublicKey{hostKey, testHostKey(t)} {
			sshProfileUnderTest.hostKey = key
			require.NoError(t, os.WriteFile(pins, []byte(sshProfileUnderTest.pin()), 0600))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			output, err := exec.CommandContext(ctx, "ssh", "-F", config, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile="+pins, "personal", "true").CombinedOutput()
			cancel()
			require.Error(t, err, "Monitor refuses interactive sessions")
			require.Equal(t, index != 0, strings.Contains(string(output), "Host key verification failed"), string(output))
			if index == 0 {
				require.Contains(t, string(output), "open failed")
			}
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetContext(ctx)
	input, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer input.Close()
	command.SetIn(input)
	command.SetOut(outputWriter)
	command.SetErr(&stderr)
	done := make(chan error, 1)
	go func() {
		err := serveMonitorPanel(command, m.client, dir, "127.0.0.1:0")
		outputWriter.Close()
		done <- err
	}()
	line, err := bufio.NewReader(outputReader).ReadString('\n')
	require.NoError(t, err)
	panelURL := strings.TrimSpace(strings.TrimPrefix(line, "Local Monitor panel: "))
	response, err := http.Get(panelURL)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("panel did not stop after cancellation")
	}
	require.NotContains(t, stderr.String(), "Press Enter", "noninteractive forwarding must not prompt")

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

// nativeSandboxTransport runs native ssh and scp with an installed sandbox profile that
// jumps through the real Monitor to a real sshd published on a sandbox reverse route.
func nativeSandboxTransport(t *testing.T, monitorAddress string, monitorKey ssh.PublicKey, monitorDir string) {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Log("native transport not exercised: no sshd")
		return
	}
	work := t.TempDir()
	hostSigner, err := ensureSSHIdentity(filepath.Join(work, "sandbox_host"), nil)
	require.NoError(t, err)
	owner := filepath.Join(work, "owner")
	ownerSigner, err := ensureSSHIdentity(owner, testSeed(t))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(work, "authorized_keys"), ssh.MarshalAuthorizedKey(ownerSigner.PublicKey()), 0o600))
	sshdAddress := freeAddress(t)
	host, port, err := net.SplitHostPort(sshdAddress)
	require.NoError(t, err)
	config := filepath.Join(work, "sshd_config")
	sftp := "/usr/lib/ssh/sftp-server"
	for _, candidate := range []string{"/usr/lib/ssh/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/libexec/sftp-server", "/usr/libexec/openssh/sftp-server"} {
		if _, err := os.Stat(candidate); err == nil {
			sftp = candidate
			break
		}
	}
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("ListenAddress %s\nPort %s\nHostKey %s\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nPidFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nSubsystem sftp %s\n",
		host, port, filepath.Join(work, "sandbox_host"), filepath.Join(work, "authorized_keys"), sftp)), 0o600))
	daemon := exec.Command(sshd, "-D", "-e", "-f", config)
	var daemonLog bytes.Buffer
	daemon.Stderr = &daemonLog
	require.NoError(t, daemon.Start())
	t.Cleanup(func() {
		daemon.Process.Kill()
		daemon.Wait()
		if t.Failed() {
			t.Log(daemonLog.String())
		}
	})
	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", sshdAddress)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	// The sandbox publishes its sshd on its reverse route with its boot host key.
	conn, err := net.Dial("tcp", monitorAddress)
	require.NoError(t, err)
	publisher, err := connectOwnerSigner(conn, "localhost", monitorKey, hostSigner, "sandbox-v2:44444444-4444-4444-8444-444444444444")
	require.NoError(t, err)
	t.Cleanup(func() { publisher.Close() })
	route, err := publisher.Listen("tcp", "127.0.0.1:22")
	require.NoError(t, err)
	go func() {
		for {
			inbound, err := route.Accept()
			if err != nil {
				return
			}
			go func() {
				defer inbound.Close()
				outbound, err := net.Dial("tcp", sshdAddress)
				if err != nil {
					return
				}
				defer outbound.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(outbound, inbound)
					outbound.(*net.TCPConn).CloseWrite()
					close(done)
				}()
				io.Copy(inbound, outbound)
				inbound.Close()
				<-done
			}()
		}
	}()

	current, err := user.Current()
	require.NoError(t, err)
	monitorHost, monitorPort, err := net.SplitHostPort(monitorAddress)
	require.NoError(t, err)
	monitorPortNumber, err := strconv.Atoi(monitorPort)
	require.NoError(t, err)
	home := t.TempDir()
	profile := sshProfile{name: "work", hostName: routeName(hostSigner.PublicKey()), port: defaultSSHPort, hostKeyAlias: "work.sandbox.example",
		user: current.Username, identityFile: owner, hostKey: hostSigner.PublicKey(), resourceID: "cp/org/user/resource",
		jump: monitorJump("work", monitorHost, monitorPortNumber, monitorDir, monitorKey, "monitor.example")}
	require.NoError(t, installSandboxAlias(profile, home))
	// ssh expands ~ from the passwd entry, so keep the run inside the temporary home.
	installed, err := os.ReadFile(filepath.Join(home, ".ssh", "tinfoil", "work.conf"))
	require.NoError(t, err)
	clientConfig := filepath.Join(home, "client_config")
	require.NoError(t, os.WriteFile(clientConfig, []byte(strings.ReplaceAll(string(installed), "~/.ssh/tinfoil/", filepath.Join(home, ".ssh", "tinfoil")+"/")), 0o600))
	native := func(stdin []byte, program string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, program, append([]string{"-F", clientConfig, "-o", "BatchMode=yes"}, args...)...)
		command.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
		command.Stdin = bytes.NewReader(stdin)
		return command.CombinedOutput()
	}
	content := []byte("written through Monitor by native ssh\n")
	remote := filepath.Join(work, "remote.txt")
	output, err := native(content, "ssh", "work", "cat > "+remote)
	require.NoError(t, err, string(output))
	output, err = native(nil, "ssh", "work", "cat "+remote)
	require.NoError(t, err, string(output))
	require.Equal(t, content, output)

	upload := filepath.Join(home, "upload.bin")
	data := make([]byte, 256<<10)
	rand.Read(data)
	require.NoError(t, os.WriteFile(upload, data, 0o600))
	output, err = native(nil, "scp", upload, "work:"+filepath.Join(work, "copied.bin"))
	require.NoError(t, err, string(output))
	output, err = native(nil, "scp", "work:"+filepath.Join(work, "copied.bin"), filepath.Join(home, "downloaded.bin"))
	require.NoError(t, err, string(output))
	downloaded, err := os.ReadFile(filepath.Join(home, "downloaded.bin"))
	require.NoError(t, err)
	require.Equal(t, data, downloaded, "scp round-trips bytes through the Monitor route")

	// A sandbox pin for another key is refused before authentication.
	profile.hostKey = testHostKey(t)
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "tinfoil", "work.known_hosts"), []byte(profile.pin()), 0o600))
	output, err = native(nil, "ssh", "work", "true")
	require.Error(t, err)
	require.Contains(t, string(output), "Host key verification failed")
}

func TestMonitorUnlockMissingDeviceKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileFile), monitorProfile{Generation: 1}, false))
	m := &monitorSession{dir: dir, keys: &resourceKeys{storageKey: testSeed(t)}}
	err := m.unlock(true)
	require.ErrorContains(t, err, "restore Monitor device key")
	require.ErrorContains(t, err, filepath.Join(dir, monitorDeviceKeyName))
	require.NoFileExists(t, filepath.Join(dir, monitorDeviceKeyName), "restoration must not replace a lost key")
}

func TestOpenMonitorBrowserOnEnter(t *testing.T) {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	} else if runtime.GOOS != "linux" {
		t.Skip("browser launch is supported on Linux and macOS")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "browser-arguments")
	t.Setenv("PATH", dir)
	t.Setenv("TINFOIL_TEST_BROWSER_RECORD", record)
	require.NoError(t, os.WriteFile(filepath.Join(dir, opener), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TINFOIL_TEST_BROWSER_RECORD\"\n"), 0700))
	const panelURL = "http://127.0.0.1:43210/app/#session=test-token"
	for _, test := range []struct {
		name     string
		input    string
		canceled bool
		opened   bool
	}{
		{name: "Enter", input: "\n", opened: true},
		{name: "CRLF", input: "\r\n", opened: true},
		{name: "EOF"},
		{name: "EOF without Enter", input: " "},
		{name: "canceled", input: "\n", canceled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			os.Remove(record)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.canceled {
				cancel()
			}
			require.NoError(t, openMonitorBrowserOnEnter(ctx, strings.NewReader(test.input), panelURL))
			args, err := os.ReadFile(record)
			if test.opened {
				require.NoError(t, err)
				require.Equal(t, panelURL+"\n", string(args), "open the exact URL, including the session fragment")
			} else {
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
	t.Run("canceled while waiting for Enter", func(t *testing.T) {
		os.Remove(record)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		input, writer := io.Pipe()
		defer input.Close()
		defer writer.Close()
		done := make(chan error, 1)
		go func() { done <- openMonitorBrowserOnEnter(ctx, input, panelURL) }()
		_, err := io.WriteString(writer, " ")
		require.NoError(t, err)
		cancel()
		_, err = io.WriteString(writer, "\n")
		require.NoError(t, err)
		require.NoError(t, <-done)
		_, err = os.Stat(record)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("launcher failure", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, opener), []byte("#!/bin/sh\nexit 7\n"), 0700))
		require.ErrorContains(t, openMonitorBrowserOnEnter(t.Context(), strings.NewReader("\n"), panelURL), "exit status 7")
	})
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
