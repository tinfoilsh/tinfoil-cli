package autounlock

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
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
		store := KeyStore{client: fake, random: bytes.NewReader(storageTestKey)}
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
		store := KeyStore{client: fake, random: &rejectingRandom{}}
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
	store := KeyStore{client: fake, random: &rejectingRandom{}}
	_, err := store.read(context.Background(), fake.secret.arn, &r)
	require.ErrorContains(t, err, "configured AWS prefix")
	require.Zero(t, fake.gets)
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

func TestStorageArtifactErrorsDoNotExposeInputCauses(t *testing.T) {
	_, err := readStorageInput(filepath.Join(t.TempDir(), storageTestEncoded), nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), storageTestEncoded)
	_, err = storageYAML([]byte("secret: *" + storageTestEncoded + "\n"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), storageTestEncoded)
}
