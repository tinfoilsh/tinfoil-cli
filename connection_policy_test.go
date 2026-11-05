package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testDigestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestTrustPathPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "known-configs.json"))
	t.Setenv(envTrust, filepath.Join(t.TempDir(), "trust.json"))
	path, err := connectionPolicyPath()
	require.NoError(t, err)
	location, err := trustLocation()
	require.NoError(t, err)
	require.Equal(t, location.Trust, path)
	t.Setenv(envTrust, "")
	path, err = connectionPolicyPath()
	require.NoError(t, err)
	require.Equal(t, location.KnownConfigs, path)
	t.Setenv(envKnownConfigs, "")
	path, err = connectionPolicyPath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".tinfoil", "trust.json"), path)
}
