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

func storageEncodedRootKeyReferences() []struct{ name, reference string } {
	key := bytes.Repeat([]byte{0xfb}, volumeKeyBytes)
	return []struct{ name, reference string }{
		{"standard", base64.StdEncoding.EncodeToString(key)},
		{"raw-standard", base64.RawStdEncoding.EncodeToString(key)},
		{"url", base64.URLEncoding.EncodeToString(key)},
		{"raw-url", base64.RawURLEncoding.EncodeToString(key)},
		{"hex", hex.EncodeToString(key)},
		{"uppercase-hex", strings.ToUpper(hex.EncodeToString(key))},
	}
}

func TestStorageRejectsRawKeyReferencesWithoutAmplification(t *testing.T) {
	for _, encoding := range storageEncodedRootKeyReferences() {
		t.Run(encoding.name, func(t *testing.T) {
			for _, reference := range []string{encoding.reference, " \n" + encoding.reference + "\r\n\t", encoding.reference[:len(encoding.reference)/2] + "\r\n" + encoding.reference[len(encoding.reference)/2:]} {
				f := newStorageCPFixture(t)
				configureStorageCLI(t)
				f.mu.Lock()
				beforeRequests := len(f.requests)
				f.mu.Unlock()
				fake := &fakeStorageAWS{describeErr: errors.New("tokenERROR " + reference)}
				random := &rejectingRandom{}
				args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", reference}, storageCLIArtifactFlags(t)...)
				out, err := executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
				require.Error(t, err)
				assert.NotContains(t, out, encoding.reference)
				assert.NotContains(t, err.Error(), encoding.reference)
				assert.NotContains(t, out, reference)
				assert.NotContains(t, err.Error(), reference)
				assert.NotContains(t, err.Error(), "tokenERROR")
				assert.Empty(t, fake.secretIDs, "raw key must not become an AWS SecretId")
				assertStorageMetadataOmits(t, encoding.reference)
				assertStorageMetadataOmits(t, reference)
				assert.Zero(t, random.calls)
				assert.Zero(t, fake.creates)
				f.mu.Lock()
				assert.Len(t, f.requests, beforeRequests, "raw keys must be rejected before any controlplane lookup")
				for _, request := range f.requests {
					assert.NotContains(t, request, encoding.reference)
				}
				f.mu.Unlock()
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
	for _, encoding := range storageEncodedRootKeyReferences() {
		reference := encoding.reference
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

func TestStorageExplicitARNDisambiguatesEncodedName(t *testing.T) {
	r := testStorageReceipt()
	r.Profile.AWSPrefix = ""
	r.Generated = false
	r.SecretName = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, volumeKeyBytes))
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	fake.secret.tags = nil
	store := volumeKeyStore{client: fake, random: &rejectingRandom{}}
	_, err := store.read(context.Background(), fake.secret.name, &r)
	require.Error(t, err)
	require.Empty(t, fake.secretIDs)
	stored, err := store.read(context.Background(), fake.secret.arn, &r)
	require.NoError(t, err)
	require.Equal(t, fake.secret.arn, stored.ARN)
}

func TestStorageEncodedKeyProviderErrorsStayRedacted(t *testing.T) {
	for _, encoding := range storageEncodedRootKeyReferences() {
		t.Run(encoding.name, func(t *testing.T) {
			newStorageCPFixture(t)
			configureStorageCLI(t)
			fake := &fakeStorageAWS{describeErr: errors.New("tokenERROR " + encoding.reference)}
			args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", "customer/original"}, storageCLIArtifactFlags(t)...)
			out, err := executeStorageCLI(t, fakeStorageFactory(fake, &rejectingRandom{}), args...)
			require.Error(t, err)
			require.NotContains(t, out, encoding.reference)
			require.NotContains(t, err.Error(), encoding.reference)
			require.NotContains(t, err.Error(), "tokenERROR")
			assertStorageMetadataOmits(t, encoding.reference)
		})
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
