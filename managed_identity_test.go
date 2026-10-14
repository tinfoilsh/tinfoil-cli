package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestEncryptedOwnerIdentityFallsBackToAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	previousStdin, previousIdentity := os.Stdin, attestSSHIdentity
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin, attestSSHIdentity = previousStdin, previousIdentity; stdin.Close() })
	credential := testOwnerCredential(t)
	private := ed25519.NewKeyFromSeed(credential.SigningSeed)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("test password"))
	require.NoError(t, err)
	attestSSHIdentity = filepath.Join(home, "encrypted-owner")
	require.NoError(t, os.WriteFile(attestSSHIdentity, pem.EncodeToMemory(block), 0600))
	socket := filepath.Join(home, "agent.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: private}))
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- agent.ServeAgent(keyring, conn)
	}()
	signer, path, closeSigner, err := ownerSigner(&ownerCredential{Version: 3, Owner: credential.publicKey()}, home)
	require.NoError(t, err)
	defer closeSigner()
	require.Equal(t, filepath.Join(home, "owner.pub"), path)
	message := []byte("prove the agent can sign without an interactive prompt")
	signature, err := signer.Sign(nil, message)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(message, signature))
	closeSigner()
	require.ErrorIs(t, <-done, io.EOF)
}

func TestLegacySandboxCredentialsRequireMatchingMonitor(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo}
	dir := filepath.Join(home, "sandboxes", row.Name)
	path := filepath.Join(dir, "monitor.json")
	require.NoError(t, writeStorageJSON(path, map[string]any{"scope": scope, "monitor": "personal"}, false))
	got, err := credentialDir(scope, row, "personal")
	require.NoError(t, err)
	require.Equal(t, dir, got)
	_, err = credentialDir(scope, row, "replacement")
	require.ErrorContains(t, err, "saved sandbox Monitor binding does not match")
	require.NoFileExists(t, filepath.Join(dir, "resource.json"))
	require.NoError(t, os.WriteFile(path, []byte("malformed metadata"), 0600))
	_, err = credentialDir(scope, row, "personal")
	require.ErrorContains(t, err, "invalid storage metadata")
}
