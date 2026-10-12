package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestUnlockUsesMeasuredSSHOwnerAndRetriesOnlyTransportFailures(t *testing.T) {
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
	var requests atomic.Int32
	bodies := make(chan []byte, 3)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, channels, global, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(global)
				for incoming := range channels {
					channel, pending, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range pending {
						var command struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "/usr/local/bin/workspace-unlock" {
							request.Reply(false, nil)
							continue
						}
						request.Reply(true, nil)
						body, err := io.ReadAll(channel)
						if err != nil {
							return
						}
						bodies <- body
						switch requests.Add(1) {
						case 1:
							return // Unlock committed, but its SSH reply was lost.
						case 2:
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						default:
							channel.Stderr().Write([]byte("409 Conflict: already unlocked"))
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
						}
						channel.Close()
						return
					}
				}
			}()
		}
	}()
	dial := func(seed []byte, pinned ssh.PublicKey) (*ssh.Client, error) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return connectOwnerSSHAs(conn, "sandbox.invalid", pinned, seed, sandboxLoginUser)
	}
	_, err = dial(bytes.Repeat([]byte{1}, 32), host.PublicKey())
	require.Error(t, err, "a different login key cannot authenticate")
	_, err = dial(credential.SigningSeed, owner)
	require.Error(t, err, "an unattested host must not receive secrets")
	require.Zero(t, requests.Load())
	keys := &sandboxKeys{diskKey: "workspace-key", monitorIdentity: "agent-private-key"}
	unlock := func() error {
		return sendOwnerRequest(func() (*ssh.Client, error) { return dial(credential.SigningSeed, host.PublicKey()) }, map[string]string{"volume": keys.diskKey, "monitor_identity": keys.monitorIdentity})
	}
	require.NoError(t, unlock())
	require.EqualValues(t, 2, requests.Load())
	first, second := <-bodies, <-bodies
	require.Equal(t, first, second)
	var sent map[string]string
	require.NoError(t, json.Unmarshal(second, &sent))
	require.Equal(t, map[string]string{"volume": keys.diskKey, "monitor_identity": keys.monitorIdentity}, sent)
	require.ErrorContains(t, unlock(), "409 Conflict: already unlocked")
	require.EqualValues(t, 3, requests.Load(), "explicit refusal must not be retried")
}

func TestOwnerLoginKeyIsDerivedAndNeverReplaced(t *testing.T) {
	credential := testOwnerCredential(t)
	path := filepath.Join(t.TempDir(), sandboxSSHKeyName)
	require.NoError(t, ensureOwnerSSHKey(path, credential.SigningSeed))
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(before)
	require.NoError(t, err)
	expected, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(credential.SigningSeed).Public())
	require.NoError(t, err)
	require.Equal(t, expected.Marshal(), signer.PublicKey().Marshal())
	require.NoError(t, ensureOwnerSSHKey(path, credential.SigningSeed))
	require.ErrorContains(t, ensureOwnerSSHKey(path, bytes.Repeat([]byte{43}, 32)), "does not match")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestUnlockRequiresUnexpiredAttestationBeforeDial(t *testing.T) {
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		session := sandboxSession{expires: expiry, keys: &sandboxKeys{dir: t.TempDir()}, profile: sshProfile{hostKey: testBootKey(t)}}
		require.ErrorContains(t, session.enroll(), "attestation expired")
	}
}
