package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go/logging"
)

const (
	volumeKeyBytes         = 64
	storageMaxPrefixLength = 400
	storageScopeTag        = "tinfoil-storage-scope"
	storageVolumeTag       = "tinfoil-volume-id"
	storageSecretField     = "value"
)

type storageSecretsAPI interface {
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type volumeKeyStore struct {
	client storageSecretsAPI
	random io.Reader
}

// Loading credentials is confined to explicit provisioning commands. SDK
// diagnostics are disabled even when CLI verbose/trace output is requested.
func newVolumeKeyStore(ctx context.Context, p storageProfile) (*volumeKeyStore, error) {
	options := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(p.AWSRegion),
		awsconfig.WithLogger(logging.Nop{}),
		awsconfig.WithClientLogMode(0),
	}
	if p.AWSProfile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(p.AWSProfile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("loading customer AWS configuration failed; check region/profile and credentials")
	}
	return volumeKeyStoreFromAWSConfig(cfg)
}

func volumeKeyStoreFromAWSConfig(cfg aws.Config) (*volumeKeyStore, error) {
	client := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.Logger = logging.Nop{}
		o.ClientLogMode = 0
	})
	if client.Options().BaseEndpoint != nil {
		return nil, fmt.Errorf("custom AWS service endpoints are unsupported for volume key custody; remove endpoint overrides")
	}
	return &volumeKeyStore{client: client, random: rand.Reader}, nil
}

func volumeSecretName(p storageProfile, id string) string {
	name := "volumes/" + id + "/key"
	if p.AWSPrefix != "" {
		name = p.AWSPrefix + "/" + name
	}
	return name
}

func volumeSecretRef(id string) string {
	return "VOLUME_" + strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_KEY"
}

type storedVolumeKey struct{ Name, ARN, Version string }

func validateExistingSecretReference(reference string) error {
	candidate := strings.TrimSpace(reference)
	if len(candidate) == base64.StdEncoding.EncodedLen(volumeKeyBytes) {
		decoded, err := base64.StdEncoding.Strict().DecodeString(candidate)
		defer clear(decoded)
		if err == nil && len(decoded) == volumeKeyBytes && base64.StdEncoding.EncodeToString(decoded) == candidate {
			return fmt.Errorf("--existing-secret looks like raw key material; provide the original AWS secret name or ARN, never its value")
		}
	}
	if len(candidate) == hex.EncodedLen(volumeKeyBytes) {
		decoded, err := hex.DecodeString(candidate)
		defer clear(decoded)
		if err == nil {
			return fmt.Errorf("--existing-secret looks like raw key material; provide the original AWS secret name or ARN, never its value")
		}
	}
	if reference == "" || candidate != reference {
		return fmt.Errorf("--existing-secret requires an AWS secret name or ARN without surrounding whitespace")
	}
	return nil
}

// No secret-bearing value or provider error crosses this adapter's boundary.
func (s *volumeKeyStore) read(ctx context.Context, reference string, provenance *storageReceipt) (storedVolumeKey, error) {
	if err := validateExistingSecretReference(reference); err != nil {
		return storedVolumeKey{}, err
	}
	desc, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(reference)})
	if err != nil {
		return storedVolumeKey{}, fmt.Errorf("AWS secret metadata read failed; verify the original reference and permissions")
	}
	if desc == nil || aws.ToString(desc.Name) == "" || aws.ToString(desc.ARN) == "" || desc.DeletedDate != nil || aws.ToBool(desc.RotationEnabled) {
		return storedVolumeKey{}, fmt.Errorf("volume secret must exist, have a stable identity, and have rotation disabled")
	}
	if provenance != nil {
		tags := map[string]string{}
		for _, tag := range desc.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		if volume, present := tags[storageVolumeTag]; present && volume != provenance.VolumeID {
			return storedVolumeKey{}, fmt.Errorf("existing secret volume provenance does not match this volume; refusing import")
		}
		if scope, present := tags[storageScopeTag]; present && scope != provenance.Profile.Scope.key() {
			return storedVolumeKey{}, fmt.Errorf("existing secret scope provenance does not match this project; refusing import")
		}
		if provenance.Generated && (aws.ToString(desc.Name) != provenance.SecretName || tags[storageScopeTag] != provenance.Profile.Scope.key() || tags[storageVolumeTag] != provenance.VolumeID) {
			return storedVolumeKey{}, fmt.Errorf("existing secret provenance does not match this volume; refusing replacement")
		}
	}
	// The keyserver resolves a name under its prefix. Reading that same name
	// and comparing ARNs prevents an explicit cross-account ARN from silently
	// preparing a policy for a different secret in the local AWS account.
	result, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: desc.Name})
	if err != nil {
		return storedVolumeKey{}, fmt.Errorf("AWS secret value read failed; no replacement key was generated")
	}
	if result == nil || result.SecretString == nil || len(result.SecretBinary) != 0 || aws.ToString(result.ARN) != aws.ToString(desc.ARN) || aws.ToString(result.VersionId) == "" {
		return storedVolumeKey{}, fmt.Errorf("AWS secret response is missing a stable JSON string version")
	}
	if provenance != nil && (provenance.Generated && aws.ToString(result.VersionId) != provenance.VolumeID || provenance.SecretVersion != "" && aws.ToString(result.VersionId) != provenance.SecretVersion || provenance.SecretARN != "" && aws.ToString(result.ARN) != provenance.SecretARN) {
		return storedVolumeKey{}, fmt.Errorf("original volume secret identity/version changed; refusing rotation")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*result.SecretString), &values); err != nil || len(values) != 1 {
		return storedVolumeKey{}, fmt.Errorf("volume secret must contain exactly one JSON string field named value")
	}
	var encoded string
	if err := json.Unmarshal(values[storageSecretField], &encoded); err != nil {
		return storedVolumeKey{}, fmt.Errorf("volume secret value must be a base64 string")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(key)
	if err != nil || len(key) != volumeKeyBytes || base64.StdEncoding.EncodeToString(key) != encoded {
		return storedVolumeKey{}, fmt.Errorf("volume secret value must be canonical standard base64 encoding of 64 bytes")
	}
	return storedVolumeKey{Name: aws.ToString(desc.Name), ARN: aws.ToString(desc.ARN), Version: aws.ToString(result.VersionId)}, nil
}

func (s *volumeKeyStore) create(ctx context.Context, r storageReceipt, beforeGenerate func() error) (storedVolumeKey, error) {
	_, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(r.SecretName)})
	if err == nil {
		return s.read(ctx, r.SecretName, &r)
	}
	var missing *types.ResourceNotFoundException
	if !errors.As(err, &missing) {
		return storedVolumeKey{}, fmt.Errorf("AWS secret existence check failed; no key generated")
	}
	if r.Phase != storagePhaseAllocated || !r.Generated {
		return storedVolumeKey{}, fmt.Errorf("existing volume has no recoverable secret; no replacement key generated")
	}
	if err := beforeGenerate(); err != nil {
		return storedVolumeKey{}, err
	}
	key := make([]byte, volumeKeyBytes)
	defer clear(key)
	if _, err := io.ReadFull(s.random, key); err != nil {
		return storedVolumeKey{}, fmt.Errorf("secure key generation failed; no secret written")
	}
	value, err := json.Marshal(map[string]string{storageSecretField: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		return storedVolumeKey{}, fmt.Errorf("encoding volume key failed")
	}
	defer clear(value)
	_, createErr := s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name: aws.String(r.SecretName), ClientRequestToken: aws.String(r.VolumeID), SecretString: aws.String(string(value)),
		Tags: []types.Tag{
			{Key: aws.String(storageScopeTag), Value: aws.String(r.Profile.Scope.key())},
			{Key: aws.String(storageVolumeTag), Value: aws.String(r.VolumeID)},
		},
	})
	// Both a successful response and an uncertain response are reconciled by
	// reading the original version; never resend a newly generated value.
	stored, readErr := s.read(ctx, r.SecretName, &r)
	if readErr != nil {
		if createErr != nil {
			return storedVolumeKey{}, fmt.Errorf("AWS CreateSecret outcome is unconfirmed; retain the volume and recover by reading its deterministic secret (no rotation)")
		}
		return storedVolumeKey{}, readErr
	}
	return stored, nil
}

func storagePolicyPath(p storageProfile, name string) (string, error) {
	if !storageNamePattern.MatchString(name) || strings.Trim(name, "/") != name {
		return "", fmt.Errorf("AWS returned an invalid secret name")
	}
	if p.AWSPrefix == "" {
		return name, nil
	}
	path, ok := strings.CutPrefix(name, p.AWSPrefix+"/")
	if !ok || path == "" || strings.Trim(path, "/") != path {
		return "", fmt.Errorf("original secret is outside the configured AWS prefix; policy would not resolve it")
	}
	return path, nil
}
