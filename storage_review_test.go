package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
)

func TestStorageReconciliationRejectsDifferentKey(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		fake := &fakeStorageAWS{beforeCreate: func(in *secretsmanager.CreateSecretInput) {
			in.SecretString = aws.String(`{"value":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, volumeKeyBytes)) + `"}`)
		}}
		if uncertain {
			fake.createErr = errors.New(storageTestEncoded)
			fake.persistOnError = true
		}
		store := volumeKeyStore{client: fake, random: bytes.NewReader(storageTestKey)}
		_, err := store.create(context.Background(), testStorageReceipt(), func() error { return nil })
		require.Error(t, err, "reconciliation must not silently accept a different key")
		require.NotContains(t, err.Error(), storageTestEncoded)
		require.Equal(t, 1, fake.creates)
	}
}

func TestStorageRejectsDuplicateSecretJSONFields(t *testing.T) {
	for _, raw := range []string{
		`{"value":"ignored","value":"` + storageTestEncoded + `"}`,
		`{"\u0076alue":"ignored","value":"` + storageTestEncoded + `"}`,
		`{"value":"` + storageTestEncoded + `","value":"` + storageTestEncoded + `"}`,
	} {
		r := testStorageReceipt()
		fake := &fakeStorageAWS{secret: testStoredSecret(r)}
		fake.secret.value = raw
		store := volumeKeyStore{client: fake, random: &rejectingRandom{}}
		_, err := store.read(context.Background(), r.SecretName, &r)
		require.Error(t, err)
		require.NotContains(t, err.Error(), storageTestEncoded)
	}
}

func TestStorageChecksPrefixBeforeReadingValue(t *testing.T) {
	r := testStorageReceipt()
	r.Generated, r.SecretName = false, "another-prefix/original-key"
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	fake.secret.tags = nil
	store := volumeKeyStore{client: fake, random: &rejectingRandom{}}
	_, err := store.read(context.Background(), fake.secret.arn, &r)
	require.ErrorContains(t, err, "configured AWS prefix")
	require.Zero(t, fake.gets)
}

func TestStorageScopeRejectsCredentialBearingURLsBeforeRequests(t *testing.T) {
	for _, variant := range []string{"userinfo", "query", "fragment"} {
		t.Run(variant, func(t *testing.T) {
			cp := newStorageCPFixture(t)
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
			out, err := executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "owner/repo", "--keyserver-url", "https://keys.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer", "--output", "json")
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

func TestStorageDebugGuardUsesYAMLBooleanType(t *testing.T) {
	for _, value := range []string{"false", "False", "FALSE"} {
		_, _, err := prepareVolumeConfig([]byte(strings.Replace(storageTestConfig, "debug: false", "debug: "+value, 1)), "https://keys.example.com", "data", "KEY", false)
		require.NoError(t, err)
	}
	for _, value := range []string{`"false"`, "true", "True", "null", "0"} {
		_, _, err := prepareVolumeConfig([]byte(strings.Replace(storageTestConfig, "debug: false", "debug: "+value, 1)), "https://keys.example.com", "data", "KEY", false)
		require.Error(t, err)
	}
}

func TestStorageDeclaredMountNamesAreNotSecretNames(t *testing.T) {
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	flags := storageCLIArtifactFlags(t)
	flags[3] = "cache.data"
	require.NoError(t, os.WriteFile(flags[7], []byte(strings.Replace(storageTestConfig, "name: data", "name: cache.data", 1)), storageFileMode))
	fake := &fakeStorageAWS{}
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.NoError(t, err)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Equal(t, 1, cp.allocations)
}

func TestStorageArtifactErrorsDoNotExposeInputCauses(t *testing.T) {
	_, err := readStorageInput(filepath.Join(t.TempDir(), storageTestEncoded))
	require.Error(t, err)
	require.NotContains(t, err.Error(), storageTestEncoded)
	_, err = storageYAML([]byte("secret: *" + storageTestEncoded + "\n"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), storageTestEncoded)
}

func TestStorageFailedUnverifiedImportCanBeCorrected(t *testing.T) {
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	r := testStorageReceipt()
	r.Profile.Scope.ControlplaneURL = cp.server.URL
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	random := &rejectingRandom{}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "auto-unlock", "configure", r.VolumeID, "--existing-secret", "customer/mistyped-reference"}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
	require.Error(t, err)
	path, err := storageMetadataPath(r.Profile.Scope, r.VolumeID)
	require.NoError(t, err)
	require.NoFileExists(t, path)
	args = append([]string{"volume", "auto-unlock", "configure", r.VolumeID, "--existing-secret", fake.secret.arn}, flags...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
	require.NoError(t, err)
	require.Zero(t, random.calls)
	require.Zero(t, fake.creates)
}
