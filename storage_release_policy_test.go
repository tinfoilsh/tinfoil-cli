package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	policyreference "github.com/tinfoilsh/tinfoil-cli/testdata/keyserverpolicy"
)

func storageTestV2WorkloadName() string {
	digest := sha256.Sum256([]byte(`{"repo":"owner/repo","tag":"v2.0.0","domain":"app.example.com"}`))
	return fmt.Sprintf("volume-%s-%x", testVolumeID, digest)
}

func storageTestConflictingV2Policy(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	conflict := fmt.Sprintf("  %s:\n    repo: another/repo\n    tag: v9.0.0\n    domain: other.example.com\n    secrets:\n      OTHER: {path: another/key, field: value}\n", storageTestV2WorkloadName())
	return append(raw, []byte(conflict)...)
}

func TestStorageNextReleaseReusesOriginalKeyAndRetainsApproval(t *testing.T) {
	commandState := newCommandFixture()

	cp := newStorageCPFixture(commandState, t)
	configureStorageCLI(commandState, t)
	v1Flags := storageCLIArtifactFlags(t)
	setStorageTestFlag(t, v1Flags, "--tag", "v1.0.0")
	fake := &fakeStorageAWS{}
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, v1Flags...)
	_, err := executeStorageCLI(commandState, t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.NoError(t, err)
	require.Equal(t, 1, fake.creates)
	originalValue, originalARN, originalVersion := fake.secret.value, fake.secret.arn, fake.secret.version
	scope := testStorageProfile().Scope
	scope.ControlplaneURL = cp.server.URL
	originalReceipt, err := loadStorageReceipt(scope, testVolumeID)
	require.NoError(t, err)
	v1ConfigPath := storageTestFlag(t, v1Flags, "--config-out")
	v1PolicyPath := storageTestFlag(t, v1Flags, "--policy-out")
	v1Config, err := os.ReadFile(v1ConfigPath)
	require.NoError(t, err)
	v1Policy, err := os.ReadFile(v1PolicyPath)
	require.NoError(t, err)
	fixtureV1, err := os.ReadFile(filepath.Join("testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	require.Equal(t, fixtureV1, v1Policy)

	v2Flags := storageCLIArtifactFlags(t)
	setStorageTestFlag(t, v2Flags, "--tag", "v2.0.0")
	setStorageTestFlag(t, v2Flags, "--config-file", v1ConfigPath)
	v2Flags = append(v2Flags, "--policy-file", v1PolicyPath)
	random := &rejectingRandom{}
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", originalARN}, v2Flags...)
	t.Logf("expected v2 workload: %s", storageTestV2WorkloadName())
	out, err := executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	require.Contains(t, out, storageUnobserved)
	v2ConfigPath := storageTestFlag(t, v2Flags, "--config-out")
	v2PolicyPath := storageTestFlag(t, v2Flags, "--policy-out")
	v2Config, err := os.ReadFile(v2ConfigPath)
	require.NoError(t, err)
	require.Equal(t, v1Config, v2Config)
	v2Policy, err := os.ReadFile(v2PolicyPath)
	require.NoError(t, err)
	fixtureV2, err := os.ReadFile(filepath.Join("testdata", "volume-policy-v1-v2.yml"))
	require.NoError(t, err)
	require.Equal(t, fixtureV2, v2Policy)
	loaded, err := policyreference.LoadPolicy(v2PolicyPath)
	require.NoError(t, err)
	require.Len(t, loaded.Workloads, 2)
	for tag, wantName := range map[string]string{"v1.0.0": "volume-" + testVolumeID, "v2.0.0": storageTestV2WorkloadName()} {
		name, workload := loaded.Match(scope.Repo, tag)
		require.Equal(t, wantName, name)
		require.NotNil(t, workload)
		require.Equal(t, "app.example.com", workload.Domain)
		refs, err := workload.Authorize(name, []string{originalReceipt.KeySecret})
		require.NoError(t, err)
		require.Equal(t, &policyreference.SecretRef{Path: "volumes/" + testVolumeID + "/key", Field: "value"}, refs[originalReceipt.KeySecret])
	}
	_, err = executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	again, err := os.ReadFile(v2PolicyPath)
	require.NoError(t, err)
	require.Equal(t, v2Policy, again)

	reuseFlags := storageCLIArtifactFlags(t)
	setStorageTestFlag(t, reuseFlags, "--tag", "v2.0.0")
	setStorageTestFlag(t, reuseFlags, "--config-file", v2ConfigPath)
	reuseFlags = append(reuseFlags, "--policy-file", v2PolicyPath)
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", originalARN}, reuseFlags...)
	_, err = executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	reused, err := os.ReadFile(storageTestFlag(t, reuseFlags, "--policy-out"))
	require.NoError(t, err)
	require.Equal(t, v2Policy, reused)
	for path, original := range map[string][]byte{v1ConfigPath: v1Config, v1PolicyPath: v1Policy, v2ConfigPath: v2Config, v2PolicyPath: v2Policy} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, original, data)
	}
	receipt, err := loadStorageReceipt(scope, testVolumeID)
	require.NoError(t, err)
	require.Equal(t, originalReceipt.Profile, receipt.Profile)
	require.Equal(t, originalReceipt.KeySecret, receipt.KeySecret)
	require.Equal(t, originalARN, receipt.SecretARN)
	require.Equal(t, originalVersion, receipt.SecretVersion)
	require.Equal(t, originalReceipt.SecretName, receipt.SecretName)
	require.Equal(t, originalReceipt.Generated, receipt.Generated)
	receiptPath, err := storageMetadataPath(scope, testVolumeID)
	require.NoError(t, err)
	beforeConflict, err := os.ReadFile(receiptPath)
	require.NoError(t, err)
	conflictPath := filepath.Join(t.TempDir(), "conflicting-policy.yml")
	conflictingPolicy := storageTestConflictingV2Policy(t)
	require.NoError(t, os.WriteFile(conflictPath, conflictingPolicy, storageFileMode))
	_, err = policyreference.LoadPolicy(conflictPath)
	require.NoError(t, err)
	conflictFlags := storageCLIArtifactFlags(t)
	setStorageTestFlag(t, conflictFlags, "--tag", "v2.0.0")
	setStorageTestFlag(t, conflictFlags, "--config-file", v1ConfigPath)
	conflictFlags = append(conflictFlags, "--policy-file", conflictPath)
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", originalARN}, conflictFlags...)
	_, err = executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.ErrorContains(t, err, "release-specific workload name")
	require.NoFileExists(t, storageTestFlag(t, conflictFlags, "--config-out"))
	require.NoFileExists(t, storageTestFlag(t, conflictFlags, "--policy-out"))
	afterConflict, err := os.ReadFile(receiptPath)
	require.NoError(t, err)
	require.Equal(t, beforeConflict, afterConflict)
	unchangedConflict, err := os.ReadFile(conflictPath)
	require.NoError(t, err)
	require.Equal(t, conflictingPolicy, unchangedConflict)
	require.Equal(t, originalValue, fake.secret.value)
	require.Equal(t, originalARN, fake.secret.arn)
	require.Equal(t, originalVersion, fake.secret.version)
	require.Zero(t, random.calls)
	require.Equal(t, 1, fake.creates)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Equal(t, 1, cp.allocations)
}
