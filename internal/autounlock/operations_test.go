package autounlock

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

func TestConfigureRecoveryPreservesPhaseAndOriginalKey(t *testing.T) {
	dir := t.TempDir()
	service := NewService(filepath.Join(dir, "storage"), strings.NewReader(storageTestConfig))
	p := testStorageProfile()
	require.NoError(t, service.SaveProfile(p))
	o := ArtifactOptions{Project: p.Scope.Repo, Mount: "data", Tag: "v1.2.3", ConfigFile: "-", ConfigOut: filepath.Join(dir, "config.yml"), PolicyOut: filepath.Join(dir, "policy.yml")}
	p, config, policy, err := service.Preflight(p.Scope, &o, false)
	require.NoError(t, err)
	require.Equal(t, []byte(storageTestConfig), config)
	fake := &fakeStorageAWS{createErr: errors.New(storageTestEncoded), persistOnError: true, getErr: errors.New(storageTestEncoded)}
	store := NewKeyStore(fake, bytes.NewReader(storageTestKey))
	request := ConfigureRequest{VolumeID: testVolumeID, OrgID: p.Scope.OrgID, Profile: p, Options: o, Config: config, Policy: policy, Fresh: true}
	_, err = service.Configure(context.Background(), store, request)
	var recovery *RecoveryError
	require.ErrorAs(t, err, &recovery)
	require.Equal(t, testVolumeID, recovery.VolumeID)
	require.Equal(t, PhaseAttempted, recovery.Receipt.Phase)
	require.Equal(t, fake.secret.name, recovery.Receipt.RecoveryReference())
	require.NotContains(t, err.Error(), storageTestEncoded)
	saved, err := service.LoadReceipt(p.Scope, testVolumeID)
	require.NoError(t, err)
	require.Equal(t, recovery.Receipt, saved)
	require.NoFileExists(t, o.ConfigOut)
	require.NoFileExists(t, o.PolicyOut)
	state, _, err := service.Status(p.Scope, testVolumeID)
	require.NoError(t, err)
	require.Equal(t, "INCOMPLETE", state)

	fake.getErr = nil
	reject := &rejectingRandom{}
	store = NewKeyStore(fake, reject)
	request.Fresh = false
	request.Options.ExistingSecret = recovery.Receipt.RecoveryReference()
	receipt, err := service.Configure(context.Background(), store, request)
	require.NoError(t, err)
	require.Equal(t, PhasePrepared, receipt.Phase)
	require.Equal(t, fake.secret.arn, receipt.SecretARN)
	require.Equal(t, fake.secret.version, receipt.SecretVersion)
	require.Zero(t, reject.calls)
	require.Equal(t, 1, fake.creates)
	state, detail, err := service.Status(p.Scope, testVolumeID)
	require.NoError(t, err)
	require.Equal(t, "CONFIGURED_LOCAL", state)
	require.Equal(t, Unobserved, detail)
}

func TestConfigureRetainsLockErrorIdentity(t *testing.T) {
	service := NewService(t.TempDir(), nil)
	p := testStorageProfile()
	path, err := service.MetadataPath(p.Scope, testVolumeID)
	require.NoError(t, err)
	unlock, err := statefile.Lock(path)
	require.NoError(t, err)
	defer unlock()
	fake := &fakeStorageAWS{}
	reject := &rejectingRandom{}
	_, err = service.Configure(context.Background(), NewKeyStore(fake, reject), ConfigureRequest{VolumeID: testVolumeID, Profile: p, Fresh: true})
	require.ErrorIs(t, err, statefile.ErrLocked)
	var recovery *RecoveryError
	require.ErrorAs(t, err, &recovery)
	require.Equal(t, PhaseAllocated, recovery.Receipt.Phase)
	require.Empty(t, fake.secretIDs)
	require.Zero(t, reject.calls)
}
