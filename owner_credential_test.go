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

const testOwnerPHC = "$argon2id$v=19$m=262144,t=3,p=4$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$h4BcgYbxSwglIl1rEHzTAlwiKVj4pBXM5TDwAfSAFEg"

func TestOwnerCredentialSharedArgonVectors(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	rawLegacy := make([]byte, 64)
	for i := range rawLegacy {
		rawLegacy[i] = byte(i)
	}
	for _, vector := range []struct {
		key  []byte
		hash string
	}{
		{[]byte("correct horse battery staple"), "h4BcgYbxSwglIl1rEHzTAlwiKVj4pBXM5TDwAfSAFEg"},
		{[]byte("  Café workspace 🔐\n"), "a0FZaNclCYyaPhjUatURHT9w5vA+/5MPWZZCRzopI1k"},
		{rawLegacy, "INvuA1i7NO31TbJ0+2IBLInzi+mNALCQRTqQr2NN4kA"},
	} {
		expected := ownerPHCPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + vector.hash
		require.Equal(t, expected, ownerPHC(vector.key, salt))
	}
}

func TestSuppliedOwnerCredentialPreservesTextAndRecognizesLegacyFiles(t *testing.T) {
	for _, size := range []int{monitorOwnerKeyBytes, sandboxDiskKeyBytes} {
		raw := bytes.Repeat([]byte{'B'}, size)
		credential, err := suppliedOwnerCredential("-", size, strings.NewReader("\n"+base64.StdEncoding.EncodeToString(raw)+"\n"))
		require.NoError(t, err)
		require.Equal(t, raw, credential.Key)
		require.True(t, credential.LegacyKey)
	}
	exact := "  Café workspace 🔐\n"
	credential, err := suppliedOwnerCredential("-", 64, strings.NewReader(exact))
	require.NoError(t, err)
	require.Equal(t, []byte(exact), credential.Key)
	require.False(t, credential.LegacyKey)
	// Nonlegacy base64 text remains a passphrase, including its whitespace.
	other := " " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'C'}, 24)) + "\n"
	credential, err = suppliedOwnerCredential("-", 64, strings.NewReader(other))
	require.NoError(t, err)
	require.Equal(t, []byte(other), credential.Key)
	for _, raw := range [][]byte{[]byte("short"), bytes.Repeat([]byte{'a'}, 4097), bytes.Repeat([]byte{0xff}, 16)} {
		_, err := suppliedOwnerCredential("-", 64, bytes.NewReader(raw))
		require.Error(t, err)
	}
	for _, size := range []int{16, 4096} {
		credential, err := suppliedOwnerCredential("-", 64, strings.NewReader(strings.Repeat("x", size)))
		require.NoError(t, err)
		require.Len(t, credential.Key, size)
	}
}

func TestOwnerCredentialRecordKeepsSaltAndNeverOverwritesKeys(t *testing.T) {
	key := []byte("correct horse battery staple")
	credential := &ownerCredential{Version: 1, Key: key, Argon2ID: testOwnerPHC}
	file := filepath.Join(t.TempDir(), "owner.key")
	require.NoError(t, saveOwnerCredential(file, credential, 32))
	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	before, err := os.ReadFile(file)
	require.NoError(t, err)
	loaded, err := readOwnerCredential(file, 32)
	require.NoError(t, err)
	require.Equal(t, credential, loaded)
	supplied, err := suppliedOwnerCredential(file, 32, nil)
	require.NoError(t, err)
	require.Equal(t, credential, supplied)
	require.NoError(t, saveOwnerCredential(file, credential, 32))
	other := *credential
	other.Key = []byte("another distinct password")
	require.ErrorContains(t, saveOwnerCredential(file, &other, 32), "different key")
	after, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, before, after)
	_, err = other.commitment(testOwnerPHC)
	require.ErrorContains(t, err, "does not match")
	_, err = other.commitment("")
	require.ErrorContains(t, err, "does not match", "a corrupt local PHC must not bind an unusable owner")

	legacy := filepath.Join(t.TempDir(), "disk.key")
	raw := bytes.Repeat([]byte{'B'}, 64)
	original := []byte(base64.StdEncoding.EncodeToString(raw) + "\n")
	require.NoError(t, os.WriteFile(legacy, original, 0600))
	parsed, err := readOwnerCredential(legacy, 64)
	require.NoError(t, err)
	require.NoError(t, saveOwnerCredential(legacy, parsed, 64))
	saved, err := os.ReadFile(legacy)
	require.NoError(t, err)
	require.Equal(t, original, saved)
}

func TestOwnerCredentialRejectsUnsupportedPHCAndConflictingBindings(t *testing.T) {
	for _, phc := range []string{
		strings.Replace(testOwnerPHC, "v=19", "v=16", 1),
		strings.Replace(testOwnerPHC, "m=262144", "m=1", 1),
		strings.Replace(testOwnerPHC, "t=3", "t=1000", 1),
		strings.Replace(testOwnerPHC, "p=4", "p=1", 1),
		testOwnerPHC + "=", strings.TrimSuffix(testOwnerPHC, "g"),
	} {
		_, err := ownerPHCSalt(phc)
		require.Error(t, err)
	}
	for _, env := range []string{
		"[SANDBOX_OWNER_KEY_SHA256=a, SANDBOX_OWNER_KEY_ARGON2ID=b]",
		"[SANDBOX_OWNER_KEY_ARGON2ID=a, SANDBOX_OWNER_KEY_ARGON2ID=b]",
	} {
		_, _, err := ownerBinding([]byte("containers:\n  - env: "+env+"\n"), sandboxOwnerEnv, sandboxArgonOwnerEnv)
		require.Error(t, err)
	}
	name, value, err := ownerBinding([]byte("containers:\n  - env: [{SANDBOX_OWNER_KEY_SHA256: ''}, {SANDBOX_OWNER_KEY_ARGON2ID: ''}]\n"), sandboxOwnerEnv, sandboxArgonOwnerEnv)
	require.NoError(t, err)
	require.Equal(t, sandboxArgonOwnerEnv, name)
	require.Empty(t, value)
}

func TestOwnerCredentialAdoptsExistingSaltWithoutChangingSecret(t *testing.T) {
	input := filepath.Join(t.TempDir(), "passphrase")
	require.NoError(t, os.WriteFile(input, []byte("correct horse battery staple"), 0600))
	config := []byte("containers:\n  - env:\n      - SANDBOX_OWNER_KEY_SHA256=\n      - SANDBOX_OWNER_KEY_ARGON2ID=" + testOwnerPHC + "\n")
	file := filepath.Join(t.TempDir(), "disk.key")
	credential, binding, err := prepareOwnerCredential(file, input, 64, config, nil, sandboxOwnerEnv, sandboxArgonOwnerEnv)
	require.NoError(t, err)
	require.Equal(t, testOwnerPHC, binding)
	require.Equal(t, testOwnerPHC, credential.Argon2ID)
	require.NoFileExists(t, file, "preflight never saves credentials before full template verification")
	legacy := []byte("containers:\n  - env: [SANDBOX_OWNER_KEY_SHA256]\n")
	_, _, err = prepareOwnerCredential(file, input, 64, nil, legacy, sandboxOwnerEnv, sandboxArgonOwnerEnv)
	require.ErrorContains(t, err, "does not support passphrases")
	var record map[string]any
	encoded, err := json.Marshal(credential)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &record))
	require.Equal(t, float64(1), record["version"])
	require.Equal(t, base64.StdEncoding.EncodeToString(credential.Key), record["key"])
}
