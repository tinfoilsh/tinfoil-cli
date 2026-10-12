package main

import (
	"bytes"
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
	_, _, err := createOwnerCredential(file, true)
	require.ErrorContains(t, err, "no local owner credential")
	require.NoFileExists(t, file)
	credential, public, err := createOwnerCredential(file, false)
	require.NoError(t, err)
	require.NotEqual(t, credential.Key, credential.SigningSeed)
	require.Equal(t, credential.publicKey(), public)
	require.NoError(t, saveOwnerCredential(file, credential))
	require.ErrorContains(t, saveOwnerCredential(file, testOwnerCredential(t)), "different credential")
	for _, exists := range []bool{false, true} {
		again, binding, err := createOwnerCredential(file, exists)
		require.NoError(t, err)
		require.Equal(t, credential, again)
		require.Equal(t, public, binding)
	}
}

func TestLegacyOwnerCredentialErrorIdentifiesFileWithoutReplacingIt(t *testing.T) {
	for _, size := range []int{32, 64} {
		file := filepath.Join(t.TempDir(), "owner.key")
		original := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, size)))
		require.NoError(t, os.WriteFile(file, original, 0600))
		for _, exists := range []bool{false, true} {
			_, _, err := createOwnerCredential(file, exists)
			require.ErrorContains(t, err, file)
			require.ErrorContains(t, err, "legacy encryption-only key")
			require.NotContains(t, err.Error(), string(original))
		}
		after, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Equal(t, original, after)
	}
}
