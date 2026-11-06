package autounlock

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storageEncodedRootKeyReferences() []struct{ name, reference string } {
	key := bytes.Repeat([]byte{0xfb}, volumeKeyBytes)
	return []struct{ name, reference string }{
		{"standard", base64.StdEncoding.EncodeToString(key)},
		{"raw-standard", base64.RawStdEncoding.EncodeToString(key)},
		{"url", base64.URLEncoding.EncodeToString(key)},
		{"raw-url", base64.RawURLEncoding.EncodeToString(key)},
		{"hex", hex.EncodeToString(key)},
		{"uppercase-hex", strings.ToUpper(hex.EncodeToString(key))},
	}
}

func TestStorageReferenceReadBoundaryRejectsRawKeysButAcceptsNames(t *testing.T) {
	for _, encoding := range storageEncodedRootKeyReferences() {
		reference := encoding.reference
		fake := &fakeStorageAWS{}
		store := KeyStore{client: fake, random: &rejectingRandom{}}
		_, err := store.read(context.Background(), reference, nil)
		require.Error(t, err)
		assert.Empty(t, fake.secretIDs)
		assert.NotContains(t, err.Error(), reference)
	}
	for _, reference := range []string{"customer/original-key", strings.Repeat("ab", 32)} {
		r := testStorageReceipt()
		r.Profile.AWSPrefix = ""
		r.SecretName, r.Generated = reference, false
		fake := &fakeStorageAWS{secret: testStoredSecret(r)}
		fake.secret.tags = nil
		store := KeyStore{client: fake, random: &rejectingRandom{}}
		stored, err := store.read(context.Background(), reference, &r)
		require.NoError(t, err)
		require.Equal(t, reference, stored.Name)
	}
}

func TestStorageExplicitARNDisambiguatesEncodedName(t *testing.T) {
	r := testStorageReceipt()
	r.Profile.AWSPrefix = ""
	r.Generated = false
	r.SecretName = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, volumeKeyBytes))
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	fake.secret.tags = nil
	store := KeyStore{client: fake, random: &rejectingRandom{}}
	_, err := store.read(context.Background(), fake.secret.name, &r)
	require.Error(t, err)
	require.Empty(t, fake.secretIDs)
	stored, err := store.read(context.Background(), fake.secret.arn, &r)
	require.NoError(t, err)
	require.Equal(t, fake.secret.arn, stored.ARN)
}
