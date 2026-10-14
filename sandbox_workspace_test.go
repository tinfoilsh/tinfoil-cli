package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkspaceKeyFollowsVolumeToNewSandbox(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	credential := testOwnerCredential(t)
	old := sandboxResource{ID: "11111111-1111-4111-8111-111111111111", Owner: credential.publicKey(), Volumes: map[string]string{"workspace": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
	oldDir := saveWorkspaceFixture(t, scope, old, credential)
	next := old
	next.ID = "22222222-2222-4222-8222-222222222222"
	dir, err := resourceDir(scope, next.ID)
	require.NoError(t, err)
	got, err := sandboxWorkspaceCredential(scope, dir, next, false)
	require.NoError(t, err)
	require.Equal(t, credential, got)
	require.FileExists(t, filepath.Join(oldDir, sandboxDiskKeyName))
	require.NoFileExists(t, filepath.Join(dir, sandboxAgentKeyName))
	require.NoFileExists(t, filepath.Join(dir, sandboxEnrolledKeyName))
	// Repeated enrollment uses the same saved key, even without a receipt yet.
	retry, err := sandboxWorkspaceCredential(scope, dir, next, false)
	require.NoError(t, err)
	require.Equal(t, got.Key, retry.Key)
}

func TestWorkspaceRecoveryStaysInAccountAndVolume(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	credential := testOwnerCredential(t)
	old := sandboxResource{ID: "11111111-1111-4111-8111-111111111111", Owner: credential.publicKey(), Volumes: map[string]string{"workspace": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
	saveWorkspaceFixture(t, scope, old, credential)
	for _, change := range []string{"account", "volume"} {
		t.Run(change, func(t *testing.T) {
			nextScope, next := scope, old
			next.ID = "22222222-2222-4222-8222-222222222222"
			if change == "account" {
				nextScope.UserID = "other"
			} else {
				next.Volumes = map[string]string{"workspace": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
			}
			dir, err := resourceDir(nextScope, next.ID)
			require.NoError(t, err)
			got, err := sandboxWorkspaceCredential(nextScope, dir, next, false)
			require.NoError(t, err)
			require.NotEqual(t, credential.Key, got.Key)
		})
	}
}

func TestWorkspaceRecoveryRefusesMissingChangedOrConflictingKeys(t *testing.T) {
	for _, failure := range []string{"missing", "owner", "conflict", "known without key"} {
		t.Run(failure, func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
			credential := testOwnerCredential(t)
			old := sandboxResource{ID: "11111111-1111-4111-8111-111111111111", Owner: credential.publicKey(), Volumes: map[string]string{"workspace": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
			oldDir := saveWorkspaceFixture(t, scope, old, credential)
			next := old
			next.ID = "22222222-2222-4222-8222-222222222222"
			switch failure {
			case "missing":
				require.NoError(t, os.Remove(filepath.Join(oldDir, sandboxDiskKeyName)))
			case "owner":
				next.Owner = testOwnerCredential(t).publicKey()
			case "conflict":
				conflict := old
				conflict.ID = "33333333-3333-4333-8333-333333333333"
				key := testOwnerCredential(t)
				key.SigningSeed = credential.SigningSeed
				saveWorkspaceFixture(t, scope, conflict, key)
			}
			dir, err := resourceDir(scope, next.ID)
			require.NoError(t, err)
			_, err = sandboxWorkspaceCredential(scope, dir, next, failure == "known without key")
			require.Error(t, err)
			require.NoFileExists(t, filepath.Join(dir, sandboxDiskKeyName))
		})
	}
}

func saveWorkspaceFixture(t *testing.T, scope accountScope, resource sandboxResource, credential *ownerCredential) string {
	t.Helper()
	dir, err := resourceDir(scope, resource.ID)
	require.NoError(t, err)
	require.NoError(t, prepareStorageDirectory(dir))
	raw, err := json.Marshal(resource)
	require.NoError(t, err)
	require.NoError(t, writeAtomic(filepath.Join(dir, "resource.json"), raw))
	require.NoError(t, saveOwnerCredential(filepath.Join(dir, sandboxDiskKeyName), credential))
	return dir
}
