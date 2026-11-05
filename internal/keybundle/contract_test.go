package keybundle

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type contractKeySyncRequest struct {
	HPKEPublicKey string `json:"hpke_pubkey"`
	Request       string `json:"request"`
	UserID        string `json:"user"`
	Account       string `json:"account"`
	Expires       int64  `json:"expires"`
}

type contractKeySyncTargets struct {
	Terminal   string `json:"terminal"`
	APIOrigin  string `json:"api_origin"`
	Callback   string `json:"callback"`
	Completion string `json:"completion"`
}

type sealedVector struct {
	SealedBy string `json:"sealed_by"`
	Envelope string `json:"envelope"`
	Payload  string `json:"payload"`
}

type ownerContractFixture struct {
	Limits struct {
		MKEnvelopeChars     int `json:"mk_envelope_chars_max"`
		MKPlaintextBytes    int `json:"mk_plaintext_bytes_max"`
		KeySyncPayloadChars int `json:"key_sync_payload_chars_max"`
		BucketChars         int `json:"bucket_chars_max"`
	} `json:"limits"`
	MK struct {
		Context      map[string]string `json:"context"`
		DEK          string            `json:"dek"`
		Plaintext    string            `json:"plaintext"`
		Envelopes    []sealedVector    `json:"envelopes"`
		WrongContext []struct {
			Case    string            `json:"case"`
			Context map[string]string `json:"context"`
		} `json:"wrong_context"`
		WrongEnvelopes    []struct{ Case, Envelope string }  `json:"wrong_envelopes"`
		WrongDEK          string                             `json:"wrong_dek"`
		InvalidPlaintexts []struct{ Case, Plaintext string } `json:"invalid_plaintexts"`
	} `json:"mk"`
	KeySync struct {
		Targets         contractKeySyncTargets `json:"targets"`
		Request         contractKeySyncRequest `json:"request"`
		RecipientKey    string                 `json:"recipient_private_key"`
		LaunchURL       string                 `json:"launch_url"`
		Canonical       string                 `json:"canonical"`
		Code            string                 `json:"code"`
		ChangedContexts []struct {
			Case    string                 `json:"case"`
			Targets contractKeySyncTargets `json:"targets"`
			Request contractKeySyncRequest `json:"request"`
			Code    string                 `json:"code"`
		} `json:"changed_context_codes"`
		EnvelopePlaintext string         `json:"envelope_plaintext"`
		Payloads          []sealedVector `json:"payloads"`
		PayloadRejects    []struct {
			Case    string                 `json:"case"`
			Request contractKeySyncRequest `json:"request"`
			Payload string                 `json:"payload"`
		} `json:"payload_rejects"`

		CompletionURL string `json:"completion_url"`
	} `json:"key_sync"`
}

func loadOwnerContract(t *testing.T) ownerContractFixture {
	raw, err := os.ReadFile("testdata/owner-contract-v1.json")
	require.NoError(t, err)
	var fixture ownerContractFixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	return fixture
}

func fixtureBytes(t *testing.T, text string) []byte {
	decoded, err := DecodeBase64URL(text, -1)
	require.NoError(t, err)
	return decoded
}

func (c contractKeySyncTargets) targets() SyncTargets {
	return SyncTargets{c.Terminal, c.APIOrigin, c.Callback, c.Completion}
}

func (c contractKeySyncRequest) request(t *testing.T) SyncRequest {
	return SyncRequest{fixtureBytes(t, c.HPKEPublicKey), c.Request, c.UserID, c.Account, c.Expires}
}

func TestOwnerContractMKOpensBothSealersAndRejectsChangedContext(t *testing.T) {
	f := loadOwnerContract(t).MK
	dek := fixtureBytes(t, f.DEK)
	context := func(m map[string]string) Context { return Context{m["api_origin"], m["user_id"], m["dek_id"]} }
	require.Len(t, f.Envelopes, 2)
	for _, sealed := range f.Envelopes {
		payload, err := Open(sealed.Envelope, dek, context(f.Context))
		require.NoError(t, err, sealed.SealedBy)
		canonical, err := Marshal(payload)
		require.NoError(t, err)
		require.Equal(t, f.Plaintext, string(canonical), sealed.SealedBy)
		for _, wrong := range f.WrongContext {
			_, err := Open(sealed.Envelope, dek, context(wrong.Context))
			require.Error(t, err, wrong.Case)
		}
		_, err = Open(sealed.Envelope, fixtureBytes(t, f.WrongDEK), context(f.Context))
		require.Error(t, err)
	}
	for _, wrong := range f.WrongEnvelopes {
		_, err := Open(wrong.Envelope, dek, context(f.Context))
		require.Error(t, err, wrong.Case)
	}
	for _, invalid := range f.InvalidPlaintexts {
		var payload Payload
		err := decodeCanonical([]byte(invalid.Plaintext), &payload)
		if err == nil {
			err = payload.validate()
		}
		require.Error(t, err, invalid.Case)
	}

	payload, err := Open(f.Envelopes[0].Envelope, dek, context(f.Context))
	require.NoError(t, err)
	resealed, err := Seal(payload, dek, context(f.Context))
	require.NoError(t, err)
	require.NotEqual(t, f.Envelopes[0].Envelope, resealed, "each seal uses a fresh nonce")
	reopened, err := Open(resealed, dek, context(f.Context))
	require.NoError(t, err)
	require.Equal(t, payload, reopened)
}

func TestOwnerContractMKBoundsAreCoherentAndCheckedBeforeDecoding(t *testing.T) {
	f := loadOwnerContract(t)
	require.Equal(t, f.Limits.MKEnvelopeChars, maxMKEnvelopeChars)
	require.Equal(t, f.Limits.MKPlaintextBytes, maxMKPlaintextBytes)
	require.Equal(t, f.Limits.KeySyncPayloadChars, MaxKeySyncPayloadChars)
	require.Equal(t, f.Limits.BucketChars, MaxBucketChars)
	envelopeChars := func(plaintext int) int {
		return len(mkEnvelopePrefix) + base64.RawURLEncoding.EncodedLen(12) + 1 + base64.RawURLEncoding.EncodedLen(plaintext+16)
	}
	require.Equal(t, maxMKEnvelopeChars, envelopeChars(maxMKPlaintextBytes))
	require.Greater(t, envelopeChars(maxMKPlaintextBytes+1), maxMKEnvelopeChars)

	dek := fixtureBytes(t, f.MK.DEK)
	context := Context{f.MK.Context["api_origin"], f.MK.Context["user_id"], f.MK.Context["dek_id"]}
	head := mkEnvelopePrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 12)) + "."
	// Well-formed base64 of zeros: at the limit it reaches decryption, one past it is refused first.
	_, err := Open(head+strings.Repeat("A", maxMKEnvelopeChars-len(head)), dek, context)
	require.Error(t, err)
	require.NotErrorIs(t, err, errMKFormat)
	_, err = Open(head+strings.Repeat("A", maxMKEnvelopeChars-len(head)+1), dek, context)
	require.ErrorIs(t, err, errMKFormat)
}

func TestOwnerContractKeySyncCodeAndEnvelope(t *testing.T) {
	f := loadOwnerContract(t).KeySync
	targets, request := f.Targets.targets(), f.Request.request(t)
	require.Equal(t, f.LaunchURL, LaunchURL(request, targets))
	require.Equal(t, f.Canonical, string(CanonicalRequest(request, targets)))
	require.Equal(t, f.Code, ConfirmationCode([]byte(f.Canonical)))

	private, err := ecdh.X25519().NewPrivateKey(fixtureBytes(t, f.RecipientKey))
	require.NoError(t, err)
	require.Equal(t, request.HPKEPublicKey, private.PublicKey().Bytes())
	require.Len(t, f.Payloads, 2)
	for _, payload := range f.Payloads {
		envelope, err := OpenSyncEnvelope(private, request, targets, payload.Payload)
		require.NoError(t, err, payload.SealedBy)
		plain, err := Marshal(envelope)
		require.NoError(t, err)
		require.Equal(t, f.EnvelopePlaintext, string(plain), payload.SealedBy)
	}
	for _, changed := range f.ChangedContexts {
		changedTargets, changedRequest := changed.Targets.targets(), changed.Request.request(t)
		code := ConfirmationCode(CanonicalRequest(changedRequest, changedTargets))
		require.Equal(t, changed.Code, code, changed.Case)
		require.NotEqual(t, f.Code, code, changed.Case)
		_, err := OpenSyncEnvelope(private, changedRequest, changedTargets, f.Payloads[0].Payload)
		require.Error(t, err, changed.Case)
	}

	for _, reject := range f.PayloadRejects {
		_, err := OpenSyncEnvelope(private, reject.Request.request(t), targets, reject.Payload)
		require.Error(t, err, reject.Case)
	}
	// Well-formed base64 at the limit reaches HPKE; one past it is refused before decoding.
	_, err = OpenSyncEnvelope(private, request, targets, strings.Repeat("A", MaxKeySyncPayloadChars))
	require.ErrorContains(t, err, "not sealed for this request")
	_, err = OpenSyncEnvelope(private, request, targets, strings.Repeat("A", MaxKeySyncPayloadChars+1))
	require.ErrorContains(t, err, "malformed key-sync callback")

	var envelope SyncEnvelope
	require.NoError(t, decodeCanonical([]byte(f.EnvelopePlaintext), &envelope))
	require.Equal(t, f.CompletionURL, CompletionURL(targets, request.Request, envelope.UserID, "org_2fixtureB"))
}

func TestBindingUUIDFormat(t *testing.T) {
	for _, id := range []string{
		"00000000-0000-0000-0000-000000000000",
		"abcdef12-3456-7890-abcd-ef1234567890",
	} {
		require.True(t, validLowerUUID(id))
	}
	for _, id := range []string{
		"ABCDEF12-3456-7890-ABCD-EF1234567890",
		"urn:uuid:abcdef12-3456-7890-abcd-ef1234567890",
		"{abcdef12-3456-7890-abcd-ef1234567890}",
		"abcdef1234567890abcdef1234567890",
		"abcdef12-3456-7890-abcd-ef1234567890\n",
		"abcdef12-3456-7890-abcd-ef123456789g",
		"abcdef12_3456-7890-abcd-ef1234567890",
	} {
		require.False(t, validLowerUUID(id), id)
	}
}
