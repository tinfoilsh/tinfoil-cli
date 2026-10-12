package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testOwnerCredential(t *testing.T) *ownerCredential {
	t.Helper()
	c, err := newSigningCredential()
	require.NoError(t, err)
	return c
}

func TestSuppliedOwnerCredentialRejectsLegacyAndMalformedFiles(t *testing.T) {
	valid, err := json.Marshal(testOwnerCredential(t))
	require.NoError(t, err)
	for _, raw := range []string{
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'B'}, 64)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'B'}, 32)),
		"short", strings.Repeat("x", 4097), string(valid) + " {}",
		strings.Replace(string(valid), `"version":2`, `"version":1`, 1),
		strings.Replace(string(valid), `"version":2`, `"version":2,"legacy_key":true`, 1),
	} {
		path := filepath.Join(t.TempDir(), "owner.json")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := readOwnerCredential(path)
		require.Error(t, err)
	}
}

func TestOwnerCredentialCreationNeverReplacesExistingKeys(t *testing.T) {
	file := filepath.Join(t.TempDir(), "owner.json")
	credential := testOwnerCredential(t)
	require.NoError(t, saveOwnerCredential(file, credential))
	require.NoError(t, saveOwnerCredential(file, credential))
	require.ErrorContains(t, saveOwnerCredential(file, testOwnerCredential(t)), "different credential")
	got, err := readOwnerCredential(file)
	require.NoError(t, err)
	require.Equal(t, credential, got)
}

func newSigningCredential() (*ownerCredential, error) {
	c := &ownerCredential{Version: 2, Key: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	if _, err := rand.Read(c.Key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(c.SigningSeed); err != nil {
		return nil, err
	}
	return c, nil
}

func TestExternalOwnerCredentialsAreScopedAndRequireRecovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	owner := testOwnerCredential(t)
	identity := filepath.Join(home, "my owner key")
	block, err := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(owner.SigningSeed), "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(identity, pem.EncodeToMemory(block), 0600))
	old := attestSSHIdentity
	attestSSHIdentity = identity
	t.Cleanup(func() { attestSSHIdentity = old })
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "one"}
	dir, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111")
	require.NoError(t, err)
	credential, err := resourceCredential(dir, "owner.key", owner.publicKey(), false)
	require.NoError(t, err)
	require.Empty(t, credential.SigningSeed)
	signer, path, close, err := ownerSigner(credential, dir)
	require.NoError(t, err)
	defer close()
	require.Equal(t, identity, path)
	expected, err := measuredOwner(owner.publicKey())
	require.NoError(t, err)
	require.Equal(t, expected.Marshal(), signer.PublicKey().Marshal())
	scope.UserID = "two"
	other, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111")
	require.NoError(t, err)
	require.NotEqual(t, dir, other)
	require.NoError(t, os.Remove(filepath.Join(dir, "owner.key")))
	_, err = resourceCredential(dir, "owner.key", owner.publicKey(), true)
	require.ErrorContains(t, err, "restore encryption credentials")
	require.NoFileExists(t, filepath.Join(dir, "owner.key"))
}
