package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func testStorageReceipt() storageReceipt {
	p := testStorageProfile()
	return storageReceipt{Version: storageSchemaVersion, Profile: p, VolumeID: testVolumeID, Mount: "data", KeySecret: volumeSecretRef(testVolumeID), SecretName: volumeSecretName(p, testVolumeID), Generated: true, Phase: storagePhaseAllocated, Tag: "v1.2.3", Domain: "app.example.com"}
}

func testStoredSecret(r storageReceipt) *fakeVolumeSecret {
	return &fakeVolumeSecret{name: r.SecretName, arn: "arn:aws:secretsmanager:us-east-2:123456789012:secret:" + r.SecretName + "-abcdef", version: r.VolumeID, value: `{"value":"` + storageTestEncoded + `"}`, tags: []types.Tag{{Key: aws.String(storageScopeTag), Value: aws.String(r.Profile.Scope.key())}, {Key: aws.String(storageVolumeTag), Value: aws.String(r.VolumeID)}}}
}

func TestStorageCreateOnlyAndUncertainResponse(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			r := testStorageReceipt()
			marked := false
			fake := &fakeStorageAWS{beforeCreate: func(in *secretsmanager.CreateSecretInput) {
				require.True(t, marked)
				require.Equal(t, r.SecretName, aws.ToString(in.Name))
				require.Equal(t, r.VolumeID, aws.ToString(in.ClientRequestToken))
				require.JSONEq(t, `{"value":"`+storageTestEncoded+`"}`, aws.ToString(in.SecretString))
				require.Empty(t, in.SecretBinary)
				require.False(t, in.ForceOverwriteReplicaSecret)
			}}
			if uncertain {
				fake.createErr = errors.New(storageTestEncoded)
				fake.persistOnError = true
			}
			store := volumeKeyStore{client: fake, random: bytes.NewReader(storageTestKey)}
			stored, err := store.create(context.Background(), r, func() error { marked = true; return nil })
			require.NoError(t, err)
			require.Equal(t, r.VolumeID, stored.Version)
			require.Equal(t, 1, fake.creates)
			reject := &rejectingRandom{}
			store.random = reject
			r.Phase = storagePhaseAttempted
			_, err = store.create(context.Background(), r, func() error { t.Fatal("unexpected generation marker"); return nil })
			require.NoError(t, err)
			require.Zero(t, reject.calls)
			require.Equal(t, 1, fake.creates)
		})
	}
}

func TestStorageNeverRegeneratesMissingExistingSecret(t *testing.T) {
	r := testStorageReceipt()
	r.Phase = storagePhaseAttempted
	reject := &rejectingRandom{}
	fake := &fakeStorageAWS{}
	store := volumeKeyStore{client: fake, random: reject}
	_, err := store.create(context.Background(), r, func() error { t.Fatal("unexpected generation marker"); return nil })
	require.ErrorContains(t, err, "no replacement key generated")
	require.Zero(t, reject.calls)
	require.Zero(t, fake.creates)
	_, err = store.read(context.Background(), r.SecretName, &r)
	require.Error(t, err)
	require.Zero(t, reject.calls)
}

func TestStorageRefusesCollisionRotationAndInvalidKeys(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*fakeVolumeSecret)
	}{
		{"wrong scope", func(s *fakeVolumeSecret) { s.tags[0].Value = aws.String("other") }},
		{"wrong volume", func(s *fakeVolumeSecret) { s.tags[1].Value = aws.String("other") }},
		{"missing tags", func(s *fakeVolumeSecret) { s.tags = nil }},
		{"rotated version", func(s *fakeVolumeSecret) { s.version = storagePreflightVolumeID }},
		{"rotation enabled", func(s *fakeVolumeSecret) { s.rotation = true }},
		{"short key", func(s *fakeVolumeSecret) {
			s.value = `{"value":"` + base64.StdEncoding.EncodeToString(storageTestKey[:63]) + `"}`
		}},
		{"long key", func(s *fakeVolumeSecret) {
			s.value = `{"value":"` + base64.StdEncoding.EncodeToString(append(bytes.Clone(storageTestKey), 1)) + `"}`
		}},
		{"raw key", func(s *fakeVolumeSecret) { s.value = storageTestEncoded }},
		{"wrong field", func(s *fakeVolumeSecret) { s.value = `{"password":"` + storageTestEncoded + `"}` }},
		{"extra field", func(s *fakeVolumeSecret) { s.value = `{"value":"` + storageTestEncoded + `","other":"x"}` }},
		{"non string", func(s *fakeVolumeSecret) { s.value = `{"value":64}` }},
		{"base64 newline", func(s *fakeVolumeSecret) { s.value = `{"value":"` + storageTestEncoded + `\n"}` }},
		{"malformed json", func(s *fakeVolumeSecret) { s.value = `{"value":"` + storageTestEncoded }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := testStorageReceipt()
			fake := &fakeStorageAWS{secret: testStoredSecret(r)}
			tt.change(fake.secret)
			reject := &rejectingRandom{}
			store := volumeKeyStore{client: fake, random: reject}
			_, err := store.create(context.Background(), r, func() error { t.Fatal("unexpected marker"); return nil })
			require.Error(t, err)
			require.NotContains(t, err.Error(), storageTestEncoded)
			require.Zero(t, reject.calls)
			require.Zero(t, fake.creates)
		})
	}
}

func TestStorageProviderErrorsNeverEscape(t *testing.T) {
	for _, operation := range []string{"describe", "get", "create", "marker"} {
		t.Run(operation, func(t *testing.T) {
			r := testStorageReceipt()
			fake := &fakeStorageAWS{}
			sensitiveErr := errors.New("provider echoed " + storageTestEncoded)
			if operation == "describe" {
				fake.describeErr = sensitiveErr
			}
			if operation == "get" {
				fake.secret = testStoredSecret(r)
				fake.getErr = sensitiveErr
			}
			if operation == "create" {
				fake.createErr = sensitiveErr
			}
			store := volumeKeyStore{client: fake, random: bytes.NewReader(storageTestKey)}
			_, err := store.create(context.Background(), r, func() error {
				if operation == "marker" {
					return errors.New("disk full")
				}
				return nil
			})
			require.Error(t, err)
			require.NotContains(t, err.Error(), storageTestEncoded)
			if operation == "marker" {
				require.Zero(t, fake.creates)
			}
		})
	}
}

func TestStorageExplicitARNReadAndVersionBinding(t *testing.T) {
	r := testStorageReceipt()
	r.Generated = false
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	fake.secret.tags = nil
	reject := &rejectingRandom{}
	store := volumeKeyStore{client: fake, random: reject}
	stored, err := store.read(context.Background(), fake.secret.arn, &r)
	require.NoError(t, err)
	path, err := storagePolicyPath(r.Profile, stored.Name)
	require.NoError(t, err)
	require.Equal(t, "volumes/"+r.VolumeID+"/key", path)
	r.SecretARN, r.SecretVersion = stored.ARN, stored.Version
	fake.secret.version = storagePreflightVolumeID
	_, err = store.read(context.Background(), fake.secret.name, &r)
	require.ErrorContains(t, err, "identity/version changed")
	require.Zero(t, reject.calls)
	require.Zero(t, fake.creates)
	_, err = storagePolicyPath(r.Profile, "another-prefix/key")
	require.Error(t, err)
}

func TestStorageOfficialSDKWire(t *testing.T) {
	fake := &fakeStorageAWS{}
	var targets []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		target := req.Header.Get("X-Amz-Target")
		mu.Lock()
		targets = append(targets, target)
		mu.Unlock()
		body, err := io.ReadAll(req.Body)
		if !assert.NoError(t, err) || !assert.Contains(t, req.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		decode := func(in any) bool {
			if !assert.NoError(t, json.Unmarshal(body, in)) {
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			return true
		}
		var result any
		switch {
		case strings.HasSuffix(target, ".DescribeSecret"):
			var in secretsmanager.DescribeSecretInput
			if !decode(&in) {
				return
			}
			result, err = fake.DescribeSecret(req.Context(), &in)
		case strings.HasSuffix(target, ".CreateSecret"):
			var in secretsmanager.CreateSecretInput
			if !decode(&in) {
				return
			}
			result, err = fake.CreateSecret(req.Context(), &in)
		case strings.HasSuffix(target, ".GetSecretValue"):
			var in secretsmanager.GetSecretValueInput
			if !decode(&in) {
				return
			}
			result, err = fake.GetSecretValue(req.Context(), &in)
		default:
			t.Errorf("unexpected write operation %s", target)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"__type": "ResourceNotFoundException", "message": "not found"}))
			return
		}
		assert.NoError(t, json.NewEncoder(w).Encode(result))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	transport := storageWireHTTP(func(req *http.Request) (*http.Response, error) {
		if !assert.Equal(t, "secretsmanager.us-east-2.amazonaws.com", req.URL.Host) {
			return nil, errors.New("unexpected AWS endpoint")
		}
		req = req.Clone(req.Context())
		req.URL.Scheme, req.URL.Host = target.Scheme, target.Host
		return server.Client().Do(req)
	})
	store, err := volumeKeyStoreFromAWSConfig(context.Background(), aws.Config{Region: "us-east-2", Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""), Logger: logging.Nop{}, HTTPClient: transport, RetryMaxAttempts: 1})
	require.NoError(t, err)
	store.random = bytes.NewReader(storageTestKey)
	stored, err := store.create(context.Background(), testStorageReceipt(), func() error { return nil })
	require.NoError(t, err)
	require.Equal(t, testVolumeID, stored.Version)
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, targets, 4)
	require.Equal(t, 1, fake.creates)
	require.Equal(t, 1, fake.gets)
}

type storageWireHTTP func(*http.Request) (*http.Response, error)

func (f storageWireHTTP) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestStorageRejectsCustomAWSEndpoints(t *testing.T) {
	_, err := volumeKeyStoreFromAWSConfig(context.Background(), aws.Config{Region: "us-east-2", BaseEndpoint: aws.String("https://not-aws.example.com"), Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", "")})
	require.ErrorContains(t, err, "custom AWS service endpoints are unsupported")
}
