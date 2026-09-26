package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func storageTestFlagIndex(t *testing.T, flags []string, name string) int {
	t.Helper()
	for i, flag := range flags {
		if flag == name && i+1 < len(flags) {
			return i + 1
		}
	}
	t.Fatalf("missing value for flag %s", name)
	return 0
}

func storageTestFlag(t *testing.T, flags []string, name string) string {
	t.Helper()
	return flags[storageTestFlagIndex(t, flags, name)]
}

func setStorageTestFlag(t *testing.T, flags []string, name, value string) {
	t.Helper()
	flags[storageTestFlagIndex(t, flags, name)] = value
}

func TestStorageArtifactFlagLookupUsesNames(t *testing.T) {
	flags := []string{"--policy-out", "policy.yml", "--tag", "v2", "--config-out", "config.yml", "--mount", "data"}
	require.Equal(t, "config.yml", storageTestFlag(t, flags, "--config-out"))
	require.Equal(t, "policy.yml", storageTestFlag(t, flags, "--policy-out"))
	setStorageTestFlag(t, flags, "--policy-out", "reviewed-policy.yml")
	require.Equal(t, "reviewed-policy.yml", storageTestFlag(t, flags, "--policy-out"))
	require.Equal(t, "config.yml", storageTestFlag(t, flags, "--config-out"))
}
