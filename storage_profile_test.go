package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageProfileRejectsInvalidKeyserverPortBeforeSaving(t *testing.T) {
	for _, endpoint := range []string{"https://keys.example.com:0", "https://keys.example.com:65536", "https://keys.example.com:999999999999999999999", "https://keys.example.com:", "https://keys.example.com?", "https://keys.example.com#", "https://[keys.example.com]", "https://2001:db8::1"} {
		t.Run(endpoint, func(t *testing.T) {
			cp := newStorageCPFixture(t)
			_, err := executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "owner/repo", "--keyserver-url", endpoint, "--aws-region", "us-east-2", "--aws-prefix", "customer")
			require.ErrorContains(t, err, "--keyserver-url")
			dir, err := storageDirectory()
			require.NoError(t, err)
			require.NoDirExists(t, dir)
			cp.mu.Lock()
			defer cp.mu.Unlock()
			require.Empty(t, cp.requests)
		})
	}
}

func TestStorageProfileAllowsHTTPSPortBoundaries(t *testing.T) {
	for _, endpoint := range []string{"https://keys.example.com", "https://keys.example.com/", "https://keys.example.com:1", "https://keys.example.com:443", "https://keys.example.com:65535", "https://[2001:db8::1]", "https://[2001:db8::1]:8443"} {
		t.Run(endpoint, func(t *testing.T) {
			p := testStorageProfile()
			p.KeyserverURL = endpoint
			require.NoError(t, p.validate())
		})
	}
}

func TestStorageInvalidSavedEndpointPreventsAllocation(t *testing.T) {
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	p := testStorageProfile()
	p.Scope.ControlplaneURL = cp.server.URL
	p.KeyserverURL = "https://keys.example.com:65536"
	path, err := storageMetadataPath(p.Scope, "")
	require.NoError(t, err)
	require.NoError(t, writeStorageJSON(path, p, false))
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), args...)
	require.ErrorContains(t, err, "--keyserver-url")
	require.NoFileExists(t, storageTestFlag(t, flags, "--config-out"))
	require.NoFileExists(t, storageTestFlag(t, flags, "--policy-out"))
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Zero(t, cp.allocations)
}
