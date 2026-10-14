package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSandboxSetupSeparatesMonitorCredentialsAndWorkspaceUnlock(t *testing.T) {
	credential := testOwnerCredential(t)
	owner, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(credential.SigningSeed).Public())
	require.NoError(t, err)
	host, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32)))
	require.NoError(t, err)
	config := &ssh.ServerConfig{PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if conn.User() != sandboxLoginUser || !bytes.Equal(owner.Marshal(), key.Marshal()) {
			return nil, errors.New("not the measured owner")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	type invocation struct {
		command string
		body    []byte
	}
	calls := make(chan invocation, 16)
	var requests, failure atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, global, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(global)
				for incoming := range channels {
					channel, pending, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for request := range pending {
						var command struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
							request.Reply(false, nil)
							continue
						}
						request.Reply(true, nil)
						body, err := io.ReadAll(channel)
						if err != nil {
							return
						}
						calls <- invocation{command.Command, body}
						requests.Add(1)
						status := uint32(0)
						switch failure.Load() {
						case 1:
							return // Reply lost: the CLI must report it, without retrying.
						case 2:
							channel.Stderr().Write([]byte("request refused"))
							status = 1
						}
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						return
					}
				}
			}()
		}
	}()
	dialAs := func(seed []byte, pinned ssh.PublicKey) (*ssh.Client, error) {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			return nil, err
		}
		return connectOwnerSSHAs(conn, "sandbox.invalid", pinned, seed, sandboxLoginUser)
	}
	_, err = dialAs(bytes.Repeat([]byte{1}, 32), host.PublicKey())
	require.Error(t, err, "a different login key cannot authenticate")
	_, err = dialAs(credential.SigningSeed, owner)
	require.Error(t, err, "an unattested host must not receive secrets")
	require.Zero(t, requests.Load())
	dial := func() (*ssh.Client, error) { return dialAs(credential.SigningSeed, host.PublicKey()) }
	private, err := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)), "agent")
	require.NoError(t, err)
	volumeKey := bytes.Repeat([]byte{0, 1, 2, 10}, 16)
	keys := &sandboxKeys{diskKey: volumeKey, monitorIdentity: string(pem.EncodeToMemory(private))}
	monitorKey := string(ssh.MarshalAuthorizedKey(host.PublicKey()))
	directory := t.TempDir()
	running := filepath.Join(directory, "systemd")
	restarted := filepath.Join(directory, "restarted")
	systemctl := filepath.Join(directory, "systemctl")
	require.NoError(t, os.WriteFile(systemctl, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(restarted)+"\n"), 0o700))
	install := func(call invocation) {
		require.Equal(t, []byte(keys.monitorIdentity), call.body, "only the private identity goes on stdin")
		// Run the actual installation script with this user's temporary directory.
		script := strings.NewReplacer("sudo -n ", "", "/run/monitor", directory,
			"-g sandbox", fmt.Sprintf("-g %d", os.Getgid()),
			"sandbox:sandbox", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"/run/systemd/system", running, "systemctl restart", systemctl+" restart").Replace(call.command)
		process := exec.Command("sh", "-c", script)
		process.Stdin = bytes.NewReader(call.body)
		output, err := process.CombinedOutput()
		require.NoError(t, err, string(output))
		for name, want := range map[string]string{"identity": keys.monitorIdentity, "known_hosts": "monitor " + monitorKey} {
			data, err := os.ReadFile(filepath.Join(directory, name))
			require.NoError(t, err)
			require.Equal(t, want, string(data))
			info, err := os.Stat(filepath.Join(directory, name))
			require.NoError(t, err)
			require.EqualValues(t, 0o600, info.Mode().Perm())
		}
	}
	require.NoError(t, configureSandbox(dial, keys, monitorKey, true))
	install(<-calls)
	require.NoFileExists(t, restarted, "initial setup runs before systemd")
	unlock := <-calls
	require.Contains(t, unlock.command, "workspace-unlock --initialize")
	require.Equal(t, volumeKey, unlock.body, "only the raw volume key goes to workspace-unlock")
	require.EqualValues(t, 2, requests.Load())

	// A Monitor reboot restores credentials and checks whether the disk is mounted.
	require.NoError(t, os.Mkdir(running, 0o700))
	monitorKey = string(ssh.MarshalAuthorizedKey(owner))
	suppliedKey := strings.TrimSpace(monitorKey) + " comment '$(touch " + filepath.Join(directory, "injected") + ")'\nignored extra line\n"
	require.NoError(t, configureSandbox(dial, keys, suppliedKey, false))
	install(<-calls)
	unlock = <-calls
	require.NotContains(t, unlock.command, "--initialize")
	require.NoFileExists(t, filepath.Join(directory, "injected"))
	output, err := os.ReadFile(restarted)
	require.NoError(t, err)
	require.Equal(t, "restart monitor-network.service\n", string(output))
	require.EqualValues(t, 4, requests.Load())

	require.NoError(t, configureSandbox(dial, keys, monitorKey, false))
	install(<-calls)
	unlock = <-calls
	require.NotContains(t, unlock.command, "--initialize")
	require.Equal(t, volumeKey, unlock.body)
	require.EqualValues(t, 6, requests.Load())

	for _, mode := range []int32{1, 2} {
		failure.Store(mode)
		before := requests.Load()
		err := configureSandbox(dial, keys, monitorKey, false)
		require.ErrorContains(t, err, "install Monitor credentials")
		if mode == 2 {
			require.ErrorContains(t, err, "request refused")
		}
		<-calls
		require.Equal(t, before+1, requests.Load(), "a failed setup must not retry or send the volume key")
	}
}

func TestUnlockRequiresUnexpiredAttestationBeforeDial(t *testing.T) {
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		session := sandboxSession{expires: expiry, keys: &sandboxKeys{dir: t.TempDir()}, profile: sshProfile{hostKey: testBootKey(t)}}
		session.monitorKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(session.profile.hostKey)))
		require.NoError(t, writeStorageJSON(filepath.Join(session.keys.dir, sandboxEnrolledKeyName), map[string]string{
			"boot_key": session.monitorKey, "monitor_key": session.monitorKey,
		}, false))
		require.ErrorContains(t, session.enroll(), "attestation expired")
	}
}
