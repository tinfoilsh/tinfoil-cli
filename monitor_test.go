package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	if _, err := os.Stat(filepath.Join(source, "routes.go")); err != nil {
		t.Skip("no Monitor checkout with routes next to tinfoil-cli")
	}
	credential := testOwnerCredential(t)
	binary := filepath.Join(t.TempDir(), "monitor")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir, build.Env = source, append(os.Environ(), "GOWORK=off")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
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
	require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileFile), monitorProfile{}, false))
	device, err := ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	conn, err := net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	_, err = connectOwnerSSHAs(conn, "localhost", hostKey, testOwnerCredential(t).SigningSeed, "owner")
	require.Error(t, err, "another key cannot enter a locked Monitor")
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	panel, err := connectOwnerSSHAs(conn, "localhost", hostKey, credential.SigningSeed, "owner")
	require.NoError(t, err, "the measured owner can enter while locked")
	defer panel.Close()
	require.Error(t, monitorOwnerRequest(panel, dir, "GET", "/policy", nil))
	require.Error(t, monitorOwnerRequest(panel, dir, "POST", "/unlock", map[string]any{"storage_key": credential.Key}), "unlock cannot initialize an empty store")
	require.NoError(t, unlockMonitor(panel, dir, credential, true))
	require.Error(t, unlockMonitor(panel, dir, testOwnerCredential(t), true), "wrong storage key refused")
	agentSigner := testSigner(t)
	agent := authorizedLine(agentSigner)

	// Exercise a sandbox reverse route through the real Monitor SSH server.
	publisherSigner := testSigner(t)
	conn, err = net.Dial("tcp", sshAddress)
	require.NoError(t, err)
	publisher, err := connectOwnerSigner(conn, "localhost", hostKey, publisherSigner, "sandbox")
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
	checkRoute := func(allowed bool) {
		t.Helper()
		signer, err := loadSigner(filepath.Join(dir, monitorDeviceKeyName))
		require.NoError(t, err)
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		client, err := connectOwnerSigner(conn, "localhost", hostKey, signer, monitorSSHUser)
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
	// A reverse SSH route works even when the sandbox has no agent identity.
	deviceSigner, err := loadSigner(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	checkEnrollment := func(enrolled bool) {
		t.Helper()
		conn, err := net.Dial("tcp", sshAddress)
		require.NoError(t, err)
		client, err := connectOwnerSigner(conn, "localhost", hostKey, deviceSigner, monitorSandboxUserPrefix+ssh.FingerprintSHA256(agentSigner.PublicKey()))
		if !enrolled {
			require.Error(t, err, "the setup handshake must reject a missing sandbox identity")
			return
		}
		require.NoError(t, err)
		defer client.Close()
		require.Contains(t, strings.Fields(string(client.ServerVersion())), monitorSandboxEnrollment)
	}
	checkEnrollment(false)
	enrollWithoutRestore := func() error {
		return monitorOwnerRequest(panel, dir, "POST", "/enroll", map[string]any{
			"device-" + storageHash([]byte(device))[:16]: map[string]any{"key": device, "routes": true},
			"sandbox-work": map[string]any{"key": agent},
		})
	}
	require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
	var beforeEnrollment, afterEnrollment monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &beforeEnrollment))
	require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &afterEnrollment))
	require.Equal(t, beforeEnrollment.Generation, afterEnrollment.Generation, "repeated enrollment must not rewrite policy")
	checkEnrollment(true)

	// With a live registration, the cached connection needs no owner key.
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	_, monitorPort, err := net.SplitHostPort(sshAddress)
	require.NoError(t, err)
	monitorPortNumber, err := strconv.Atoi(monitorPort)
	require.NoError(t, err)
	target := &workloadTarget{containerView: containerView{
		ID: "11111111-1111-4111-8111-111111111111", Name: "test-monitor", Repo: monitorRepo,
		Domain: "localhost", Status: statusRunning, SSHPort: monitorPortNumber}, source: monitorRepo,
		env: map[string]string{monitorOwnerEnv: credential.publicKey()}}
	cachedDir, err := monitorRecord(scope, target)
	require.NoError(t, err)
	devicePrivate, err := os.ReadFile(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cachedDir, monitorDeviceKeyName), devicePrivate, 0600))
	_, err = updateProfile(cachedDir, func(p *monitorProfile) error {
		p.Address, p.HostKey, p.ConfigSource, p.Generation = sshAddress, authorizedLine(hostSigner), monitorRepo, 1
		return nil
	})
	require.NoError(t, err)
	session := &sandboxSession{box: containerView{Name: "work"}, keys: &sandboxKeys{agentKey: agent}, initialized: true}
	require.NoError(t, session.configureMonitor(scope, target, false))
	session.close()
	require.NoFileExists(t, filepath.Join(cachedDir, monitorOwnerKeyName))

	name := "device-" + storageHash([]byte(device))[:16]
	for _, change := range []map[string]any{
		{"path": []string{"identities", name, "routes"}, "value": false},
		{"path": []string{"identities", name}, "delete": true},
	} {
		require.NoError(t, monitorOwnerRequest(panel, dir, "POST", "/policy/edits", map[string]any{"changes": []any{change}}))
		checkRoute(false)
		require.NoError(t, unlockMonitor(panel, dir, credential, false))
		checkRoute(false)
		checkEnrollment(false)
		require.ErrorContains(t, enrollWithoutRestore(), "revoked")
		require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
		checkRoute(true)
		checkEnrollment(true)
		var before, after monitorProfile
		require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &before))
		require.NoError(t, unlockMonitor(panel, dir, credential, true))
		require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &after))
		require.Equal(t, before.Generation, after.Generation, "unchanged open must not rewrite Monitor state")
	}
	require.NoError(t, monitorOwnerRequest(panel, dir, "POST", "/policy/edits", map[string]any{
		"changes": []any{map[string]any{"path": []string{"identities", "sandbox-work"}, "delete": true}},
	}))
	checkRoute(true)
	checkEnrollment(false)
	require.ErrorContains(t, enrollWithoutRestore(), "revoked")
	session = &sandboxSession{box: containerView{Name: "work"}, keys: &sandboxKeys{agentKey: agent}, initialized: true}
	defer session.close()
	require.ErrorContains(t, session.configureMonitor(scope, target, false), "restore encryption credentials", "missing live registration must require owner enrollment despite the saved receipt")
	require.NoError(t, pairSandboxMonitor(panel, dir, "work", device, agent))
	checkEnrollment(true)
	require.NoError(t, session.configureMonitor(scope, target, false))
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
	require.ErrorContains(t, unlockMonitor(panel, dir, credential, true), "older than")
	_, err = updateProfile(dir, func(p *monitorProfile) error { p.Generation -= 5; return nil })
	require.NoError(t, err)

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
		err := serveMonitorPanel(command, panel, dir, "127.0.0.1:0")
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
}

func TestMonitorSetupUsesOnlyHandshakeWhenEnrollmentIsChecked(t *testing.T) {
	for _, checked := range []bool{true, false} {
		t.Run(strconv.FormatBool(checked), func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
			target := &workloadTarget{containerView: containerView{
				ID: "11111111-1111-4111-8111-111111111111", Name: "test-monitor", Domain: "localhost", Status: statusRunning, SSHPort: 22},
				source: monitorRepo, env: map[string]string{monitorOwnerEnv: testOwnerCredential(t).publicKey()}}
			dir, err := monitorRecord(scope, target)
			require.NoError(t, err)
			_, err = ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
			require.NoError(t, err)
			host, agent := testSigner(t), testSigner(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
			if checked {
				config.ServerVersion = "SSH-2.0-Go " + monitorSandboxEnrollment
			}
			config.AddHostKey(host)
			type observation struct {
				user     string
				requests int
				err      error
			}
			observed := make(chan observation, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					observed <- observation{err: err}
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					observed <- observation{err: err}
					return
				}
				defer server.Close()
				result := observation{user: server.User()}
				for channels != nil || requests != nil {
					select {
					case channel, ok := <-channels:
						if !ok {
							channels = nil
							continue
						}
						result.requests++
						channel.Reject(ssh.Prohibited, "unexpected setup request")
					case request, ok := <-requests:
						if !ok {
							requests = nil
							continue
						}
						result.requests++
						request.Reply(false, nil)
					}
				}
				observed <- result
			}()
			_, err = updateProfile(dir, func(p *monitorProfile) error {
				p.Address, p.HostKey, p.ConfigSource, p.Generation = listener.Addr().String(), authorizedLine(host), monitorRepo, 1
				return nil
			})
			require.NoError(t, err)
			session := &sandboxSession{box: containerView{Name: "work"}, keys: &sandboxKeys{agentKey: authorizedLine(agent)}, initialized: true}
			defer session.close()
			err = session.configureMonitor(scope, target, false)
			if checked {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "restore encryption credentials", "a Monitor that ignores the setup username must require owner enrollment")
			}
			session.close()
			select {
			case result := <-observed:
				require.NoError(t, result.err)
				require.Equal(t, monitorSandboxUserPrefix+ssh.FingerprintSHA256(agent.PublicKey()), result.user)
				require.Zero(t, result.requests, "registration must be checked without another SSH channel or request")
			case <-time.After(5 * time.Second):
				t.Fatal("setup connection did not close")
			}
		})
	}
}

func TestMonitorUnlockMissingDeviceKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileFile), monitorProfile{Generation: 1}, false))
	err := unlockMonitor(nil, dir, testOwnerCredential(t), true)
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

func connectOwnerSSHAs(conn net.Conn, host string, hostKey ssh.PublicKey, seed []byte, user string) (*ssh.Client, error) {
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, err
	}
	return connectOwnerSigner(conn, host, hostKey, signer, user)
}
