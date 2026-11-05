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
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
	"golang.org/x/crypto/ssh"
)

func TestManagedTrustPrecedesCredentials(t *testing.T) {
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	for _, test := range []struct{ kind, prefix string }{{"sandbox", "/tinfoil/containers"}, {"monitor", "/tinfoil/containers"}, {"monitor", "/acme/confidential-agent-monitor"}, {"sandbox", "/user-9c4a7f21-e0b8-36d5-6a13-c8fe42d907ab/confidential-agent-sandbox"}} {
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

type monitorTestVerifier struct{ host ssh.PublicKey }

func (v monitorTestVerifier) MonitorHost(string, string) (ssh.PublicKey, error) { return v.host, nil }
func (v monitorTestVerifier) DirectHost(context.Context, string, string) (owner.VerifiedHost, error) {
	panic("unexpected sandbox verification")
}
func (v monitorTestVerifier) RelayHost(string, string, []byte, []byte) (owner.VerifiedHost, error) {
	panic("unexpected sandbox verification")
}

func TestMonitorPanelAndNativeTransportAgainstRealMonitor(t *testing.T) {
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
	home := t.TempDir()
	seed := testSeed(t)
	identity := filepath.Join(home, "owner")
	require.NoError(t, ensureOwnerSSHKey(identity, seed))
	hostPath := filepath.Join(home, "host")
	hostSigner, err := ensureSSHIdentity(hostPath, nil)
	require.NoError(t, err)
	sshAddress := freeAddress(t)
	cmd := exec.Command(binary, "-production", "-ssh-host-key", hostPath, "-bucket", "file://"+t.TempDir()+"?no_tmp_dir=1", "-api", freeAddress(t), "-listen", sshAddress)
	cmd.Env = append(os.Environ(), "MONITOR_OWNER_PUBLIC_KEY="+ed25519PublicKeyString(seed))
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
		conn, err := net.Dial("tcp", sshAddress)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)
	host, port, err := net.SplitHostPort(sshAddress)
	require.NoError(t, err)
	number, err := strconv.Atoi(port)
	require.NoError(t, err)
	scope := owner.Scope{ControlplaneURL: "https://cp.example", UserID: "user_owner"}
	row := owner.Workload{Container: containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "monitor", Domain: host, SSHPort: number, Status: statusRunning, OwnerKeyMode: "umk", OwnerPublicKey: ed25519PublicKeyString(seed)}, Environment: map[string]string{monitorOwnerEnv: ed25519PublicKeyString(seed), "TINFOIL_STORAGE_BUCKET": "s3://bucket?prefix=containers%2F" + storageHash([]byte("user:user_owner")) + "%2Fresource%2F&region=us-east-1"}}
	service := &owner.Service{ConfigPath: filepath.Join(home, "config.json"), Home: func() (string, error) { return home, nil }, IdentityFile: identity}
	session, err := service.ConnectMonitor(t.Context(), scope, nil, &row, true, monitorTestVerifier{host: hostSigner.PublicKey()})
	require.NoError(t, err)
	defer session.Close()
	dir, err := owner.ResourceDir(service.ConfigPath, scope, row.ID, row.Name)
	require.NoError(t, err)
	nativeSandboxTransport(t, sshAddress, hostSigner.PublicKey(), dir)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetContext(ctx)
	input, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer input.Close()
	command.SetIn(input)
	command.SetOut(writer)
	command.SetErr(&stderr)
	done := make(chan error, 1)
	go func() {
		err := serveMonitorPanel(command, &monitorSession{session}, "127.0.0.1:0")
		writer.Close()
		done <- err
	}()
	line, err := bufio.NewReader(reader).ReadString('\n')
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
	identity := filepath.Join(work, "owner")
	ownerSigner, err := ensureSSHIdentity(identity, testSeed(t))
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
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("ListenAddress %s\nPort %s\nHostKey %s\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nPidFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nSubsystem sftp %s\n", host, port, filepath.Join(work, "sandbox_host"), filepath.Join(work, "authorized_keys"), sftp)), 0o600))
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
				go func() { io.Copy(outbound, inbound); outbound.(*net.TCPConn).CloseWrite(); close(done) }()
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
	profile := sshProfile{name: "work", hostName: routeName(hostSigner.PublicKey()), port: defaultSSHPort, hostKeyAlias: "work.sandbox.example", user: current.Username, identityFile: identity, hostKey: hostSigner.PublicKey(), resourceID: "cp/org/user/resource", jump: monitorJump("work", monitorHost, monitorPortNumber, monitorDir, monitorKey, "monitor.example")}
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
		name, input      string
		canceled, opened bool
	}{{name: "Enter", input: "\n", opened: true}, {name: "CRLF", input: "\r\n", opened: true}, {name: "EOF"}, {name: "EOF without Enter", input: " "}, {name: "canceled", input: "\n", canceled: true}} {
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
