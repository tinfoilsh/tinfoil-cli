package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func TestCredentialCompatibility(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	t.Setenv("SSH_AUTH_SOCK", "")
	owner := testOwnerCredential(t)
	identity := filepath.Join(home, "external-owner")
	require.NoError(t, ensureOwnerSSHKey(identity, owner.SigningSeed))
	old := attestSSHIdentity
	attestSSHIdentity = identity
	t.Cleanup(func() { attestSSHIdentity = old })
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "one"}
	for _, repository := range []string{monitorRepo, defaultSandboxRepo} {
		for _, legacy := range []bool{false, true} {
			row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: repository}
			want, err := resourceDir(scope, row.ID)
			require.NoError(t, err)
			if legacy {
				want = filepath.Join(home, "sandboxes", row.Name)
				if repository == monitorRepo {
					data, _ := json.Marshal(scope)
					want = filepath.Join(home, "monitors", storageHash(data), row.Name)
					require.NoError(t, writeStorageJSON(filepath.Join(want, monitorProfileFile), monitorProfile{}, false))
				} else {
					require.NoError(t, writeStorageJSON(filepath.Join(want, "monitor.json"), map[string]any{"scope": scope}, false))
				}
			}
			dir, err := credentialDir(scope, row)
			require.NoError(t, err)
			require.Equal(t, want, dir)
			require.NoError(t, prepareStorageDirectory(dir))
			file := filepath.Join(dir, "credential-"+strings.TrimPrefix(repository, "tinfoilsh/"))
			credential := &ownerCredential{Version: 3, Owner: owner.publicKey(), Key: owner.Key}
			if legacy {
				credential = owner
			}
			require.NoError(t, saveOwnerCredential(file, credential))
			before, err := os.ReadFile(file)
			require.NoError(t, err)
			loaded, err := resourceCredential(dir, filepath.Base(file), owner.publicKey(), true)
			require.NoError(t, err)
			signer, path, close, err := ownerSigner(loaded, dir)
			require.NoError(t, err)
			close()
			expected, err := measuredOwner(owner.publicKey())
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), signer.PublicKey().Marshal())
			if legacy {
				require.Equal(t, filepath.Join(dir, sandboxSSHKeyName), path)
				_, _, _, err = ownerSigner(testOwnerCredential(t), dir)
				require.ErrorContains(t, err, "does not match")
			} else {
				require.Equal(t, identity, path)
			}
			after, err := os.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, before, after, "reading either version must preserve its encryption key and file")
			other := scope
			other.UserID = "two"
			foreign, err := credentialDir(other, row)
			require.NoError(t, err)
			require.NotEqual(t, dir, foreign)
			require.NoError(t, os.Remove(file))
			_, err = resourceCredential(dir, filepath.Base(file), owner.publicKey(), true)
			require.ErrorContains(t, err, "restore encryption credentials")
			require.NoFileExists(t, file)
		}
	}
	_, err := credentialDir(scope, containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "../escape"})
	require.Error(t, err)
}
