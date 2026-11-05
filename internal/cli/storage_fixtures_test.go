package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const (
	storageDirMode           = 0o700
	storageFileMode          = 0o600
	volumeKeyBytes           = 64
	storageScopeTag          = "tinfoil-storage-scope"
	storageVolumeTag         = "tinfoil-volume-id"
	storagePreflightVolumeID = "00000000-0000-4000-8000-000000000000"
	storagePhaseAllocated    = autounlock.PhaseAllocated
	storagePhaseAttempted    = autounlock.PhaseAttempted
	storagePhaseStored       = autounlock.PhaseStored
	storagePhaseVerifying    = autounlock.PhaseVerifying
)

func writeStorageJSON(path string, value any, exclusive bool) error {
	return statefile.WriteJSON(path, value, exclusive)
}

func acquireStorageLock(path string) (func(), error) {
	return statefile.Lock(path)
}

func storageMetadataPath(scope storageScope, volume string) (string, error) {
	service, err := newStorageService(nil)
	if err != nil {
		return "", err
	}
	return service.MetadataPath(scope, volume)
}

func loadStorageProfile(scope storageScope) (storageProfile, error) {
	service, err := newStorageService(nil)
	if err != nil {
		return storageProfile{}, err
	}
	return service.LoadProfile(scope)
}

func loadStorageReceipt(scope storageScope, volume string) (storageReceipt, error) {
	service, err := newStorageService(nil)
	if err != nil {
		return storageReceipt{}, err
	}
	return service.LoadReceipt(scope, volume)
}

var storageTestKey = bytes.Repeat([]byte{73}, volumeKeyBytes)
var storageTestEncoded = base64.StdEncoding.EncodeToString(storageTestKey)

type fakeVolumeSecret struct {
	name, arn, version, value string
	tags                      []types.Tag
	rotation                  bool
}

type fakeStorageAWS struct {
	mu             sync.Mutex
	secret         *fakeVolumeSecret
	creates        int
	gets           int
	secretIDs      []string
	describeErr    error
	getErr         error
	createErr      error
	persistOnError bool
	beforeCreate   func(*secretsmanager.CreateSecretInput)
}

func (f *fakeStorageAWS) DescribeSecret(_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secretIDs = append(f.secretIDs, aws.ToString(in.SecretId))
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if f.secret == nil || aws.ToString(in.SecretId) != f.secret.name && aws.ToString(in.SecretId) != f.secret.arn {
		return nil, &types.ResourceNotFoundException{}
	}
	s := f.secret
	return &secretsmanager.DescribeSecretOutput{Name: aws.String(s.name), ARN: aws.String(s.arn), Tags: s.tags, RotationEnabled: aws.Bool(s.rotation)}, nil
}

func (f *fakeStorageAWS) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secretIDs = append(f.secretIDs, aws.ToString(in.SecretId))
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.secret == nil || aws.ToString(in.SecretId) != f.secret.arn && aws.ToString(in.SecretId) != f.secret.name {
		return nil, &types.ResourceNotFoundException{}
	}
	s := f.secret
	return &secretsmanager.GetSecretValueOutput{Name: aws.String(s.name), ARN: aws.String(s.arn), VersionId: aws.String(s.version), SecretString: aws.String(s.value)}, nil
}

func (f *fakeStorageAWS) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.beforeCreate != nil {
		f.beforeCreate(in)
	}
	if f.secret != nil {
		return nil, &types.ResourceExistsException{Message: aws.String(storageTestEncoded)}
	}
	if f.createErr != nil && !f.persistOnError {
		return nil, f.createErr
	}
	f.secret = &fakeVolumeSecret{name: aws.ToString(in.Name), arn: "arn:aws:secretsmanager:us-east-2:123456789012:secret:" + aws.ToString(in.Name) + "-abcdef", version: aws.ToString(in.ClientRequestToken), value: aws.ToString(in.SecretString), tags: in.Tags}
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &secretsmanager.CreateSecretOutput{Name: in.Name, ARN: aws.String(f.secret.arn), VersionId: in.ClientRequestToken}, nil
}

type rejectingRandom struct{ calls int }

func (r *rejectingRandom) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("randomness must not be used")
}

func testStorageProfile() storageProfile {
	return storageProfile{Version: storageSchemaVersion, Scope: storageScope{ControlplaneURL: "https://api.example.com", OrgID: "org_test", Repo: "owner/repo"}, KeyserverURL: "https://keys.example.com", AWSRegion: "us-east-2", AWSPrefix: "customer", Domain: "app.example.com"}
}

func volumeSecretName(p storageProfile, id string) string {
	return p.AWSPrefix + "/volumes/" + id + "/key"
}

func testStorageReceipt() storageReceipt {
	p := testStorageProfile()
	return storageReceipt{Version: storageSchemaVersion, Profile: p, VolumeID: testVolumeID, Mount: "data", KeySecret: "VOLUME_" + strings.ToUpper(strings.ReplaceAll(testVolumeID, "-", "_")) + "_KEY", SecretName: volumeSecretName(p, testVolumeID), Generated: true, Phase: storagePhaseAllocated, Tag: "v1.2.3", Domain: "app.example.com"}
}

func testStoredSecret(r storageReceipt) *fakeVolumeSecret {
	return &fakeVolumeSecret{name: r.SecretName, arn: "arn:aws:secretsmanager:us-east-2:123456789012:secret:" + r.SecretName + "-abcdef", version: r.VolumeID, value: `{"value":"` + storageTestEncoded + `"}`, tags: []types.Tag{{Key: aws.String(storageScopeTag), Value: aws.String(r.Profile.Scope.Key())}, {Key: aws.String(storageVolumeTag), Value: aws.String(r.VolumeID)}}}
}

type storageWireHTTP func(*http.Request) (*http.Response, error)

func (f storageWireHTTP) Do(req *http.Request) (*http.Response, error) { return f(req) }

const storageTestConfig = `# deployment comment
cpus: 2
memory: 8192
debug: false
future-setting: {enabled: true} # unknown stays
containers:
  - name: app
    image: ghcr.io/owner/app:latest
    args: ["-v", "/mnt/data:/data"] # mount stays
volumes:
  - name: data # disk stays
    mount: /mnt/data
    future-volume-setting: keep
`
