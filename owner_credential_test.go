package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testOwnerCredential(t *testing.T) *ownerCredential {
	t.Helper()
	c := &ownerCredential{Version: 2, Key: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	_, err := rand.Read(c.Key)
	require.NoError(t, err)
	_, err = rand.Read(c.SigningSeed)
	require.NoError(t, err)
	return c
}

func ensureOwnerSSHKey(path string, seed []byte) error {
	_, err := ensureSSHIdentity(path, seed)
	return err
}

func TestOwnerCredentialCompatibilityAndCustody(t *testing.T) {
	dir, owner := t.TempDir(), testOwnerCredential(t)
	old := attestSSHIdentity
	attestSSHIdentity = filepath.Join(dir, "identity")
	t.Cleanup(func() { attestSSHIdentity = old })
	require.NoError(t, ensureOwnerSSHKey(attestSSHIdentity, owner.SigningSeed))
	for _, version := range []int{2, 3} {
		c := *owner
		c.Version = version
		if version == 3 {
			c.Owner, c.SigningSeed = owner.publicKey(), nil
		}
		file := fmt.Sprint(version)
		path := filepath.Join(dir, file)
		require.NoError(t, saveOwnerCredential(path, &c))
		require.NoError(t, saveOwnerCredential(path, &c))
		require.ErrorContains(t, saveOwnerCredential(path, testOwnerCredential(t)), "different credential")
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		loaded, err := resourceCredential(dir, file, owner.publicKey(), true)
		require.NoError(t, err)
		signer, _, close, err := ownerSigner(loaded, dir)
		require.NoError(t, err)
		close()
		expected, err := measuredOwner(owner.publicKey())
		require.NoError(t, err)
		require.Equal(t, expected.Marshal(), signer.PublicKey().Marshal())
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.NoError(t, os.Remove(path))
		_, err = resourceCredential(dir, file, owner.publicKey(), true)
		require.ErrorContains(t, err, "restore encryption credentials")
		require.NoFileExists(t, path)
	}
	valid, err := json.Marshal(owner)
	require.NoError(t, err)
	for _, raw := range []string{"short", strings.Repeat("x", 4097), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), string(valid) + " {}", strings.Replace(string(valid), `"version":2`, `"version":1`, 1), strings.Replace(string(valid), `"version":2`, `"version":2,"unknown":true`, 1)} {
		path := filepath.Join(dir, "invalid")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := readOwnerCredential(path)
		require.Error(t, err)
	}
}

func TestConcurrentSSHKeyCreationPreservesWinner(t *testing.T) {
	for _, seed := range [][]byte{nil, testOwnerCredential(t).SigningSeed} {
		path := filepath.Join(t.TempDir(), "identity")
		results := make(chan ssh.Signer, 16)
		for range 16 {
			go func() {
				signer, err := ensureSSHIdentity(path, seed)
				if err != nil {
					t.Error(err)
				}
				results <- signer
			}()
		}
		first := <-results
		require.NotNil(t, first)
		for range 15 {
			signer := <-results
			require.NotNil(t, signer)
			require.Equal(t, first.PublicKey().Marshal(), signer.PublicKey().Marshal())
		}
		require.ErrorContains(t, ensureOwnerSSHKey(path, testOwnerCredential(t).SigningSeed), "does not match")
	}
}

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

func TestWorkspaceCredentialsFollowOnlyTheirAccountAndVolume(t *testing.T) {
	for _, mode := range []string{"reuse", "account", "volume", "owner", "missing", "conflict", "known without key"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
			c := testOwnerCredential(t)
			row := sandboxResource{ID: "11111111-1111-4111-8111-111111111111", Owner: c.publicKey(), Volumes: map[string]string{"workspace": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
			save := func(row sandboxResource, key *ownerCredential) string {
				dir, err := resourceDir(scope, row.ID)
				require.NoError(t, err)
				require.NoError(t, writeStorageJSON(filepath.Join(dir, "resource.json"), row, false))
				require.NoError(t, saveOwnerCredential(filepath.Join(dir, sandboxDiskKeyName), key))
				return dir
			}
			oldDir := save(row, c)
			row.ID = "22222222-2222-4222-8222-222222222222"
			switch mode {
			case "account":
				scope.UserID = "other"
			case "volume":
				row.Volumes["workspace"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			case "owner":
				row.Owner = testOwnerCredential(t).publicKey()
			case "missing":
				require.NoError(t, os.Remove(filepath.Join(oldDir, sandboxDiskKeyName)))
			case "conflict":
				other := row
				other.ID = "33333333-3333-4333-8333-333333333333"
				key := *c
				key.Key = make([]byte, 32)
				save(other, &key)
			}
			dir, err := resourceDir(scope, row.ID)
			require.NoError(t, err)
			got, err := sandboxWorkspaceCredential(scope, dir, row, mode == "known without key")
			switch mode {
			case "reuse", "account", "volume":
				require.NoError(t, err)
				require.Equal(t, mode == "reuse", string(c.Key) == string(got.Key))
				require.NoFileExists(t, filepath.Join(dir, sandboxAgentKeyName))
				again, err := sandboxWorkspaceCredential(scope, dir, row, true)
				require.NoError(t, err)
				require.Equal(t, got.Key, again.Key)
			default:
				require.Error(t, err)
				require.NoFileExists(t, filepath.Join(dir, sandboxDiskKeyName))
			}
		})
	}
}
