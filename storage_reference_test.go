package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertStorageMetadataOmits(t *testing.T, value string) {
	t.Helper()
	dir, err := storageDirectory()
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(data), value, "storage metadata must not retain unverified input")
	}
}

func TestStorageRejectsRawKeyReferencesWithoutAmplification(t *testing.T) {
	key := bytes.Repeat([]byte{0xa3}, volumeKeyBytes)
	for _, encoding := range []struct{ name, reference string }{
		{"base64", base64.StdEncoding.EncodeToString(key)},
		{"hex", hex.EncodeToString(key)},
	} {
		t.Run(encoding.name, func(t *testing.T) {
			f := newStorageCPFixture(t)
			configureStorageCLI(t)
			fake := &fakeStorageAWS{describeErr: errors.New("provider echoed " + encoding.reference)}
			random := &rejectingRandom{}
			args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", encoding.reference}, storageCLIArtifactFlags(t)...)
			out, err := executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
			require.Error(t, err)
			assert.NotContains(t, out, encoding.reference)
			assert.NotContains(t, err.Error(), encoding.reference)
			assert.Empty(t, fake.secretIDs, "raw key must not become an AWS SecretId")
			assertStorageMetadataOmits(t, encoding.reference)
			assert.Zero(t, random.calls)
			assert.Zero(t, fake.creates)
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, request := range f.requests {
				assert.NotContains(t, request, encoding.reference)
			}
		})
	}
}

func TestStorageUnresolvedReferenceIsNotSavedOrEchoed(t *testing.T) {
	newStorageCPFixture(t)
	configureStorageCLI(t)
	const reference = "customer/unverified-original-name"
	fake := &fakeStorageAWS{describeErr: errors.New("provider echoed " + storageTestEncoded)}
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", reference}, storageCLIArtifactFlags(t)...)
	out, err := executeStorageCLI(t, fakeStorageFactory(fake, &rejectingRandom{}), args...)
	require.Error(t, err)
	assert.NotContains(t, out, reference)
	assert.NotContains(t, err.Error(), reference)
	assertStorageMetadataOmits(t, reference)
}

func TestStorageReferenceReadBoundaryRejectsRawKeysButAcceptsNames(t *testing.T) {
	for _, reference := range []string{storageTestEncoded, hex.EncodeToString(storageTestKey)} {
		fake := &fakeStorageAWS{}
		store := volumeKeyStore{client: fake, random: &rejectingRandom{}}
		_, err := store.read(context.Background(), reference, nil)
		require.Error(t, err)
		assert.Empty(t, fake.secretIDs)
		assert.NotContains(t, err.Error(), reference)
	}
	for _, reference := range []string{"customer/original-key", strings.Repeat("ab", 32)} {
		r := testStorageReceipt()
		r.Profile.AWSPrefix = ""
		r.SecretName, r.Generated = reference, false
		fake := &fakeStorageAWS{secret: testStoredSecret(r)}
		fake.secret.tags = nil
		store := volumeKeyStore{client: fake, random: &rejectingRandom{}}
		stored, err := store.read(context.Background(), reference, &r)
		require.NoError(t, err)
		require.Equal(t, reference, stored.Name)
	}
}

func TestStorageDropsPreviouslyUnverifiedReceiptName(t *testing.T) {
	f := newStorageCPFixture(t)
	configureStorageCLI(t)
	r := testStorageReceipt()
	r.Profile.Scope.ControlplaneURL = f.server.URL
	r.Generated, r.SecretName, r.Phase = false, storageTestEncoded, storagePhaseVerifying
	path, err := storageMetadataPath(r.Profile.Scope, r.VolumeID)
	require.NoError(t, err)
	require.NoError(t, writeStorageJSON(path, r, true))
	fake := &fakeStorageAWS{}
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", "customer/unresolved"}, storageCLIArtifactFlags(t)...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, &rejectingRandom{}), args...)
	require.Error(t, err)
	assertStorageMetadataOmits(t, storageTestEncoded)
}
