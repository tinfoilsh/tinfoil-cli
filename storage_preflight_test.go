package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/smithy-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageKnownPreflightFailuresDoNotAllocate(t *testing.T) {
	for _, variant := range []string{"missing-profile", "symlink-metadata"} {
		t.Run(variant, func(t *testing.T) {
			cp := newStorageCPFixture(t)
			profileArgs := []string{"project", "storage", "configure", "owner/repo", "--keyserver-url", "https://keys.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer", "--domain", "app.example.com"}
			if variant == "missing-profile" {
				profileArgs = append(profileArgs, "--aws-profile", "missing-test-profile")
			}
			_, err := executeStorageCLI(t, forbiddenStorageFactory(t), profileArgs...)
			require.NoError(t, err)
			fake := &fakeStorageAWS{}
			random := &rejectingRandom{}
			factory := fakeStorageFactory(fake, random)
			if variant == "missing-profile" {
				empty := filepath.Join(t.TempDir(), "empty-aws-config")
				require.NoError(t, os.WriteFile(empty, nil, storageFileMode))
				factory = func(ctx context.Context, p storageProfile) (*volumeKeyStore, error) {
					_, err := awsconfig.LoadDefaultConfig(ctx,
						awsconfig.WithSharedConfigProfile(p.AWSProfile),
						awsconfig.WithSharedConfigFiles([]string{empty}),
						awsconfig.WithSharedCredentialsFiles([]string{empty}),
						awsconfig.WithRegion(p.AWSRegion),
						awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test-access", "test-secret", "")),
						awsconfig.WithLogger(logging.Nop{}),
						awsconfig.WithHTTPClient(storageWireHTTP(func(*http.Request) (*http.Response, error) {
							t.Error("AWS network access is forbidden")
							return nil, errors.New("network forbidden")
						})),
					)
					require.Error(t, err, "isolated SDK must reject the configured missing profile")
					return nil, errors.New("loading customer AWS configuration failed")
				}
			} else {
				dir, err := storageDirectory()
				require.NoError(t, err)
				target := filepath.Join(filepath.Dir(dir), "storage-target")
				require.NoError(t, os.Rename(dir, target))
				require.NoError(t, os.Symlink(target, dir))
			}
			args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, storageCLIArtifactFlags(t)...)
			out, err := executeStorageCLI(t, factory, args...)
			require.Error(t, err)
			assert.NotContains(t, out, "retained")
			assert.Zero(t, fake.creates)
			assert.Zero(t, random.calls)
			cp.mu.Lock()
			defer cp.mu.Unlock()
			assert.Zero(t, cp.allocations, "known setup failure must precede volume allocation")
		})
	}
}

func TestStorageCredentialFailuresPrecedeAllocationAndStayRedacted(t *testing.T) {
	for _, variant := range []string{"provider-error", "empty-credentials", "no-provider"} {
		t.Run(variant, func(t *testing.T) {
			cp := newStorageCPFixture(t)
			configureStorageCLI(t)
			retrievals := 0
			factory := func(ctx context.Context, p storageProfile) (*volumeKeyStore, error) {
				cfg := aws.Config{Region: p.AWSRegion, HTTPClient: storageWireHTTP(func(*http.Request) (*http.Response, error) {
					t.Error("preflight must not perform a secret mutation or network probe")
					return nil, errors.New("network forbidden")
				})}
				if variant != "no-provider" {
					cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
						retrievals++
						if variant == "provider-error" {
							return aws.Credentials{}, errors.New("credential provider echoed " + storageTestEncoded)
						}
						return aws.Credentials{}, nil
					})
				}
				return volumeKeyStoreFromAWSConfig(ctx, cfg)
			}
			args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, storageCLIArtifactFlags(t)...)
			_, err := executeStorageCLI(t, factory, args...)
			require.ErrorContains(t, err, "credentials")
			if variant != "no-provider" {
				require.Equal(t, 1, retrievals)
			}
			cp.mu.Lock()
			defer cp.mu.Unlock()
			require.Zero(t, cp.allocations)
		})
	}
}

func TestStorageUnwritableOutputsFailBeforeAllocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory write permissions")
	}
	cp := newStorageCPFixture(t)
	configureStorageCLI(t)
	flags := storageCLIArtifactFlags(t)
	dir := filepath.Dir(flags[9])
	require.NoError(t, os.Chmod(dir, 0o500))
	defer os.Chmod(dir, storageDirMode)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(t, forbiddenStorageFactory(t), args...)
	require.ErrorContains(t, err, "not writable")
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Zero(t, cp.allocations)
}

func TestStorageWriteProbeLeavesDirectoryUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.json")
	const original = "existing metadata\n"
	require.NoError(t, os.WriteFile(path, []byte(original), storageFileMode))
	require.NoError(t, probeStorageDirectory(dir))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(data))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
