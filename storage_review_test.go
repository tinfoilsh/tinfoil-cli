package main

import (
	"bytes"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageScopeRejectsCredentialBearingURLsBeforeRequests(t *testing.T) {
	commandState := newCommandFixture()

	for _, variant := range []string{"userinfo", "query", "fragment"} {
		t.Run(variant, func(t *testing.T) {
			cp := newStorageCPFixture(commandState, t)
			u, err := url.Parse(cp.server.URL)
			require.NoError(t, err)
			const private = "private-url-credential"
			switch variant {
			case "userinfo":
				u.User = url.UserPassword("user", private)
			case "query":
				u.RawQuery = "token=" + private
			case "fragment":
				u.Fragment = private
			}
			t.Setenv(envCPURL, u.String())
			out, err := executeStorageCLI(commandState, t, forbiddenStorageFactory(t), "project", "storage", "configure", "owner/repo", "--keyserver-url", "https://keys.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer", "--output", "json")
			require.Error(t, err)
			require.NotContains(t, err.Error(), private)
			require.NotContains(t, out, private)
			dir, err := storageDirectory()
			require.NoError(t, err)
			require.NoDirExists(t, dir)
			cp.mu.Lock()
			defer cp.mu.Unlock()
			require.Empty(t, cp.requests)
		})
	}
}

func TestStorageDeclaredMountNamesAreNotSecretNames(t *testing.T) {
	commandState := newCommandFixture()

	cp := newStorageCPFixture(commandState, t)
	configureStorageCLI(commandState, t)
	flags := storageCLIArtifactFlags(t)
	flags[3] = "cache.data"
	require.NoError(t, os.WriteFile(flags[7], []byte(strings.Replace(storageTestConfig, "name: data", "name: cache.data", 1)), storageFileMode))
	fake := &fakeStorageAWS{}
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(commandState, t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.NoError(t, err)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Equal(t, 1, cp.allocations)
}

func TestStorageFailedUnverifiedImportCanBeCorrected(t *testing.T) {
	commandState := newCommandFixture()

	cp := newStorageCPFixture(commandState, t)
	configureStorageCLI(commandState, t)
	r := testStorageReceipt()
	r.Profile.Scope.ControlplaneURL = cp.server.URL
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	random := &rejectingRandom{}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "auto-unlock", "configure", r.VolumeID, "--existing-secret", "customer/mistyped-reference"}, flags...)
	_, err := executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.Error(t, err)
	path, err := storageMetadataPath(r.Profile.Scope, r.VolumeID)
	require.NoError(t, err)
	require.NoFileExists(t, path)
	args = append([]string{"volume", "auto-unlock", "configure", r.VolumeID, "--existing-secret", fake.secret.arn}, flags...)
	_, err = executeStorageCLI(commandState, t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	require.Zero(t, random.calls)
	require.Zero(t, fake.creates)
}
