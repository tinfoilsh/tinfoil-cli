package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mappedStorageAWS struct {
	*fakeStorageAWS
	secrets map[string]*fakeStorageAWS
}

func (m *mappedStorageAWS) DescribeSecret(ctx context.Context, in *secretsmanager.DescribeSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	if fake := m.secrets[aws.ToString(in.SecretId)]; fake != nil {
		return fake.DescribeSecret(ctx, in, opts...)
	}
	return nil, &types.ResourceNotFoundException{}
}

func (m *mappedStorageAWS) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if fake := m.secrets[aws.ToString(in.SecretId)]; fake != nil {
		return fake.GetSecretValue(ctx, in, opts...)
	}
	return nil, &types.ResourceNotFoundException{}
}

func TestStorageFirstImportRejectsForeignProvenanceWithoutBinding(t *testing.T) {
	for _, variant := range []string{"volume", "scope", "volume-only", "scope-only", "empty-volume"} {
		t.Run(variant, func(t *testing.T) {
			cp := newStorageCPFixture(t)
			configureStorageCLI(t)
			a := testStorageReceipt()
			a.Profile.Scope.ControlplaneURL = cp.server.URL
			b := a
			b.VolumeID = storagePreflightVolumeID
			b.SecretName = volumeSecretName(b.Profile, b.VolumeID)
			original := &fakeStorageAWS{secret: testStoredSecret(a)}
			foreign := &fakeStorageAWS{secret: testStoredSecret(b)}
			switch variant {
			case "scope":
				foreign.secret.tags[0].Value = aws.String("other-scope")
				foreign.secret.tags[1].Value = aws.String(a.VolumeID)
			case "volume-only":
				foreign.secret.tags = foreign.secret.tags[1:]
			case "scope-only":
				foreign.secret.tags = []types.Tag{{Key: aws.String(storageScopeTag), Value: aws.String("other-scope")}}
			case "empty-volume":
				foreign.secret.tags[1].Value = aws.String("")
			}
			mapped := &mappedStorageAWS{fakeStorageAWS: &fakeStorageAWS{}, secrets: map[string]*fakeStorageAWS{
				original.secret.name: original, original.secret.arn: original,
				foreign.secret.name: foreign, foreign.secret.arn: foreign,
			}}
			random := &rejectingRandom{}
			factory := func(context.Context, storageProfile) (*volumeKeyStore, error) {
				return &volumeKeyStore{client: mapped, random: random}, nil
			}
			flags := storageCLIArtifactFlags(t)
			const originalArtifact = "reviewed artifact must remain unchanged\n"
			for _, path := range []string{flags[9], flags[11]} {
				require.NoError(t, os.WriteFile(path, []byte(originalArtifact), storageFileMode))
			}
			args := append([]string{"volume", "auto-unlock", "configure", a.VolumeID, "--existing-secret", foreign.secret.arn}, flags...)
			_, err := executeStorageCLI(t, factory, args...)
			assert.ErrorContains(t, err, "provenance")
			assert.Zero(t, foreign.gets, "foreign key must not be read")
			path, pathErr := storageMetadataPath(a.Profile.Scope, a.VolumeID)
			require.NoError(t, pathErr)
			assert.NoFileExists(t, path, "rejected first import must not bind a receipt")
			for _, path := range []string{flags[9], flags[11]} {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, originalArtifact, string(data))
			}
			args = append([]string{"volume", "auto-unlock", "configure", a.VolumeID, "--existing-secret", original.secret.name}, storageCLIArtifactFlags(t)...)
			out, err := executeStorageCLI(t, factory, args...)
			require.NoError(t, err)
			assert.Contains(t, out, "CONFIGURED_LOCAL")
			receipt, err := loadStorageReceipt(a.Profile.Scope, a.VolumeID)
			require.NoError(t, err)
			assert.Equal(t, original.secret.arn, receipt.SecretARN)
			assert.Equal(t, original.secret.version, receipt.SecretVersion)
			assert.Zero(t, random.calls)
			assert.Zero(t, mapped.creates)
		})
	}
}
