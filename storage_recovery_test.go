package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
)

func TestStorageFailedReleasePreparationCannotKeepConfiguredStatus(t *testing.T) {
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	r := testStorageReceipt()
	r.Profile.Scope.ControlplaneURL = cp.server.URL
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	reject := &rejectingRandom{}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.name}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.NoError(t, err)
	flags = storageCLIArtifactFlags(t)
	flags[5] = "v2.0.0"
	fake.getErr = errors.New(storageTestEncoded)
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.name}, flags...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.Error(t, err)
	out, err := executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "auto-unlock", "status", testVolumeID, "--project", "owner/repo")
	require.NoError(t, err)
	require.Contains(t, out, "INCOMPLETE")
	require.NotContains(t, out, "CONFIGURED_LOCAL")
	fake.getErr = nil
	out, err = executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.NoError(t, err)
	require.Contains(t, out, "--version v2.0.0")
	require.Contains(t, out, storageUnobserved)
	require.Zero(t, fake.creates)
	require.Zero(t, reject.calls)
}

func TestStorageMissingFirstWriteStaysIncomplete(t *testing.T) {
	f := newStorageCPFixture(t)
	configureStorageCLI(t)
	fake := &fakeStorageAWS{createErr: errors.New(storageTestEncoded)}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.ErrorContains(t, err, storagePhaseAttempted)
	reject := &rejectingRandom{}
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", volumeSecretName(testStorageProfile(), testVolumeID)}, flags...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.ErrorContains(t, err, "retained")
	require.Zero(t, reject.calls)
	require.Equal(t, 1, fake.creates)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 1, f.allocations)
}

func TestStorageArtifactFailureRecoversOriginalKey(t *testing.T) {
	newStorageCPFixture(t)
	configureStorageCLI(t)
	flags := storageCLIArtifactFlags(t)
	fake := &fakeStorageAWS{beforeCreate: func(*secretsmanager.CreateSecretInput) {
		require.NoError(t, os.Mkdir(flags[11], storageDirMode))
	}}
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.ErrorContains(t, err, storagePhaseStored)
	require.FileExists(t, flags[9])
	require.NoError(t, os.Remove(flags[11]))
	reject := &rejectingRandom{}
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.name}, flags...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.NoError(t, err)
	require.Zero(t, reject.calls)
	require.Equal(t, 1, fake.creates)
}

func TestStorageCustodyRecordsAreExclusiveAndMalformedDataFailsClosed(t *testing.T) {
	newStorageCPFixture(t)
	configureStorageCLI(t)
	scope := testStorageProfile().Scope
	scope.ControlplaneURL = os.Getenv(envCPURL)
	path, err := storageMetadataPath(scope, testVolumeID)
	require.NoError(t, err)
	unlock, err := acquireStorageLock(path)
	require.NoError(t, err)
	_, err = acquireStorageLock(path)
	require.ErrorContains(t, err, "locked")
	unlock()
	unlock, err = acquireStorageLock(path)
	require.NoError(t, err)
	unlock()
	r := testStorageReceipt()
	r.Profile.Scope = scope
	require.NoError(t, writeStorageJSON(path, r, true))
	require.Error(t, writeStorageJSON(path, r, true))
	require.NoError(t, os.WriteFile(path, []byte("malformed "+storageTestEncoded), storageFileMode))
	_, err = loadStorageReceipt(scope, testVolumeID)
	require.ErrorContains(t, err, "invalid storage metadata")
	require.NotContains(t, err.Error(), storageTestEncoded)
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", r.SecretName}, storageCLIArtifactFlags(t)...)
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), args...)
	require.ErrorContains(t, err, "invalid storage metadata")
}
