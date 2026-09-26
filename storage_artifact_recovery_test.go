package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	storageReadOnlyDirMode  = 0o500
	storageReadOnlyFileMode = 0o400
)

type storageArtifactRecoveryFixture struct {
	cp          *storageCPFixture
	aws         *fakeStorageAWS
	random      *rejectingRandom
	args        []string
	flags       []string
	receiptPath string
}

func prepareStorageArtifactRecovery(t *testing.T) storageArtifactRecoveryFixture {
	t.Helper()
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	r := testStorageReceipt()
	r.Profile.Scope.ControlplaneURL = cp.server.URL
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	random := &rejectingRandom{}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.arn}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	path, err := storageMetadataPath(r.Profile.Scope, r.VolumeID)
	require.NoError(t, err)
	return storageArtifactRecoveryFixture{cp: cp, aws: fake, random: random, args: args, flags: flags, receiptPath: path}
}

type readOnlyArtifactSnapshot struct {
	data []byte
	info os.FileInfo
}

func makeStorageArtifactsReadOnly(t *testing.T, flags []string) (string, map[string]readOnlyArtifactSnapshot) {
	t.Helper()
	snapshots := map[string]readOnlyArtifactSnapshot{}
	for _, path := range []string{flags[9], flags[11]} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			snapshots[path] = readOnlyArtifactSnapshot{}
			continue
		}
		require.NoError(t, err)
		require.NoError(t, os.Chmod(path, storageReadOnlyFileMode))
		info, err := os.Stat(path)
		require.NoError(t, err)
		snapshots[path] = readOnlyArtifactSnapshot{data: data, info: info}
	}
	dir := filepath.Dir(flags[9])
	require.NoError(t, os.Chtimes(dir, time.Unix(0, 0), time.Unix(0, 0)))
	require.NoError(t, os.Chmod(dir, storageReadOnlyDirMode))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, storageDirMode)) })
	return dir, snapshots
}

func assertStorageArtifactsUntouched(t *testing.T, dir string, snapshots map[string]readOnlyArtifactSnapshot) {
	t.Helper()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.EqualValues(t, storageReadOnlyDirMode, info.Mode().Perm())
	require.True(t, info.ModTime().Equal(time.Unix(0, 0)), "output directory must not be probed or written")
	for path, snapshot := range snapshots {
		if snapshot.info == nil {
			require.NoFileExists(t, path)
			continue
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, snapshot.data, data)
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.True(t, os.SameFile(snapshot.info, info))
		require.Equal(t, snapshot.info.ModTime(), info.ModTime())
		require.EqualValues(t, storageReadOnlyFileMode, info.Mode().Perm())
	}
}

func TestStorageReadOnlyMatchingArtifactRecovery(t *testing.T) {
	for _, withoutReceipt := range []bool{false, true} {
		f := prepareStorageArtifactRecovery(t)
		if withoutReceipt {
			require.NoError(t, os.Remove(f.receiptPath))
		}
		dir, snapshots := makeStorageArtifactsReadOnly(t, f.flags)
		gets := f.aws.gets
		out, err := executeStorageCLI(t, fakeStorageFactory(f.aws, f.random), f.args...)
		require.NoError(t, err)
		require.Contains(t, out, "CONFIGURED_LOCAL")
		require.Equal(t, gets+1, f.aws.gets)
		require.FileExists(t, f.receiptPath)
		require.Zero(t, f.aws.creates)
		require.Zero(t, f.random.calls)
		assertStorageArtifactsUntouched(t, dir, snapshots)
	}
}

func TestStorageReadOnlyConflictingOrMissingArtifactsDoNotMutateReceipt(t *testing.T) {
	for _, variant := range []string{"different-config", "different-policy", "missing-config-different-policy", "missing-config", "missing-policy"} {
		t.Run(variant, func(t *testing.T) {
			if os.Geteuid() == 0 && (variant == "missing-config" || variant == "missing-policy") {
				t.Skip("root bypasses directory write permissions")
			}
			f := prepareStorageArtifactRecovery(t)
			before, err := os.ReadFile(f.receiptPath)
			require.NoError(t, err)
			switch variant {
			case "different-config":
				require.NoError(t, os.WriteFile(f.flags[9], []byte("different config\n"), storageFileMode))
			case "different-policy":
				require.NoError(t, os.WriteFile(f.flags[11], []byte("different policy\n"), storageFileMode))
			case "missing-config-different-policy":
				require.NoError(t, os.Remove(f.flags[9]))
				require.NoError(t, os.WriteFile(f.flags[11], []byte("different policy\n"), storageFileMode))
			case "missing-config":
				require.NoError(t, os.Remove(f.flags[9]))
			case "missing-policy":
				require.NoError(t, os.Remove(f.flags[11]))
			}
			dir, snapshots := makeStorageArtifactsReadOnly(t, f.flags)
			_, err = executeStorageCLI(t, fakeStorageFactory(f.aws, f.random), f.args...)
			if strings.Contains(variant, "different") {
				require.ErrorContains(t, err, "different contents")
			} else {
				require.ErrorContains(t, err, "not writable")
			}
			after, err := os.ReadFile(f.receiptPath)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, f.aws.creates)
			require.Zero(t, f.random.calls)
			assertStorageArtifactsUntouched(t, dir, snapshots)
			f.cp.mu.Lock()
			defer f.cp.mu.Unlock()
			for _, request := range f.cp.requests {
				require.True(t, strings.HasPrefix(request, "GET "), "no mutating controlplane request: %s", request)
			}
		})
	}
}

func TestStorageMatchingArtifactsStillRequireReceiptLock(t *testing.T) {
	f := prepareStorageArtifactRecovery(t)
	dir, snapshots := makeStorageArtifactsReadOnly(t, f.flags)
	unlock, err := acquireStorageLock(f.receiptPath)
	require.NoError(t, err)
	defer unlock()
	before, err := os.ReadFile(f.receiptPath)
	require.NoError(t, err)
	_, err = executeStorageCLI(t, fakeStorageFactory(f.aws, f.random), f.args...)
	require.ErrorContains(t, err, "locked")
	after, err := os.ReadFile(f.receiptPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	assertStorageArtifactsUntouched(t, dir, snapshots)
}

func TestStorageMatchingReadOnlyOutputAllowsOtherWritableOutput(t *testing.T) {
	f := prepareStorageArtifactRecovery(t)
	f.flags[11] = filepath.Join(t.TempDir(), "new-policy.yml")
	f.args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", f.aws.secret.arn}, f.flags...)
	dir, snapshots := makeStorageArtifactsReadOnly(t, f.flags)
	_, err := executeStorageCLI(t, fakeStorageFactory(f.aws, f.random), f.args...)
	require.NoError(t, err)
	require.FileExists(t, f.flags[11])
	delete(snapshots, f.flags[11])
	assertStorageArtifactsUntouched(t, dir, snapshots)
	require.Zero(t, f.aws.creates)
	require.Zero(t, f.random.calls)
}
