package cli

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
	location, err := trustLocation()
	require.NoError(t, err)
	path, err := location.Path()
	require.NoError(t, err)
	require.Equal(t, location.Trust, path)
	t.Setenv(envTrust, "")
	location, err = trustLocation()
	require.NoError(t, err)
	path, err = location.Path()
	require.NoError(t, err)
	require.Equal(t, location.KnownConfigs, path)
	t.Setenv(envKnownConfigs, "")
	location, err = trustLocation()
	require.NoError(t, err)
	path, err = location.Path()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".tinfoil", "trust.json"), path)
}
