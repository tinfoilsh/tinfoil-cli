package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	OwnerRequest struct {
		Seed     string `json:"seed"`
		Owner    string `json:"owner"`
		Requests []struct {
			Name      string `json:"name"`
			InnerBody string `json:"inner_body"`
			Bytes     string `json:"bytes"`
			Signature string `json:"signature"`
			Envelope  string `json:"envelope"`
		} `json:"requests"`
		ServerRejects []struct {
			Case      string         `json:"case"`
			Bytes     string         `json:"bytes"`
			Signature string         `json:"signature"`
			Server    map[string]any `json:"server"`
			Error     *string        `json:"error"`
		} `json:"server_rejects"`
		InvalidRequests []struct{ Case, Bytes string } `json:"invalid_requests"`
	} `json:"owner_request"`
	KeySync struct {
		Targets      contractKeySyncTargets `json:"targets"`
		Request      contractKeySyncRequest `json:"request"`
		RecipientKey string                 `json:"recipient_private_key"`
		LaunchURL    string                 `json:"launch_url"`
		Canonical    string                 `json:"canonical"`
		Code         string                 `json:"code"`
		CodeInputs   []struct {
			Input   string `json:"input"`
			Matches bool   `json:"matches"`
		} `json:"code_inputs"`
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
	SandboxEHBPKey struct {
		SPKIHex string `json:"spki_hex"`
		RawHex  string `json:"raw_hex"`
		Reject  []struct {
			Case    string `json:"case"`
			SPKIHex string `json:"spki_hex"`
		} `json:"reject"`
	} `json:"sandbox_ehbp_key"`
}

func loadOwnerContract(t *testing.T) ownerContractFixture {
	raw, err := os.ReadFile("testdata/owner-contract-v1.json")
	require.NoError(t, err)
	var fixture ownerContractFixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	return fixture
}

func fixtureBytes(t *testing.T, text string) []byte {
	decoded, err := decodeB64U(text, -1)
	require.NoError(t, err)
	return decoded
}

func (c contractKeySyncTargets) targets() keySyncTargets {
	return keySyncTargets{c.Terminal, c.APIOrigin, c.Callback, c.Completion}
}

func (c contractKeySyncRequest) request(t *testing.T) keySyncRequest {
	return keySyncRequest{fixtureBytes(t, c.HPKEPublicKey), c.Request, c.UserID, c.Account, c.Expires}
}

func TestOwnerContractMKOpensBothSealersAndRejectsChangedContext(t *testing.T) {
	f := loadOwnerContract(t).MK
	dek := fixtureBytes(t, f.DEK)
	context := func(m map[string]string) mkContext { return mkContext{m["api_origin"], m["user_id"], m["dek_id"]} }
	require.Len(t, f.Envelopes, 2)
	for _, sealed := range f.Envelopes {
		payload, err := openMK(sealed.Envelope, dek, context(f.Context))
		require.NoError(t, err, sealed.SealedBy)
		canonical, err := contractJSON(payload)
		require.NoError(t, err)
		require.Equal(t, f.Plaintext, string(canonical), sealed.SealedBy)
		for _, wrong := range f.WrongContext {
			_, err := openMK(sealed.Envelope, dek, context(wrong.Context))
			require.Error(t, err, wrong.Case)
		}
		_, err = openMK(sealed.Envelope, fixtureBytes(t, f.WrongDEK), context(f.Context))
		require.Error(t, err)
	}
	for _, wrong := range f.WrongEnvelopes {
		_, err := openMK(wrong.Envelope, dek, context(f.Context))
		require.Error(t, err, wrong.Case)
	}
	for _, invalid := range f.InvalidPlaintexts {
		var payload mkPayload
		err := decodeCanonical([]byte(invalid.Plaintext), &payload)
		if err == nil {
			err = payload.validate()
		}
		require.Error(t, err, invalid.Case)
	}

	payload, err := openMK(f.Envelopes[0].Envelope, dek, context(f.Context))
	require.NoError(t, err)
	resealed, err := sealMK(payload, dek, context(f.Context))
	require.NoError(t, err)
	require.NotEqual(t, f.Envelopes[0].Envelope, resealed, "each seal uses a fresh nonce")
	reopened, err := openMK(resealed, dek, context(f.Context))
	require.NoError(t, err)
	require.Equal(t, payload, reopened)
}

func TestOwnerContractMKBoundsAreCoherentAndCheckedBeforeDecoding(t *testing.T) {
	f := loadOwnerContract(t)
	require.Equal(t, f.Limits.MKEnvelopeChars, maxMKEnvelopeChars)
	require.Equal(t, f.Limits.MKPlaintextBytes, maxMKPlaintextBytes)
	require.Equal(t, f.Limits.KeySyncPayloadChars, maxKeySyncPayloadChars)
	require.Equal(t, f.Limits.BucketChars, maxBucketChars)
	envelopeChars := func(plaintext int) int {
		return len(mkEnvelopePrefix) + base64.RawURLEncoding.EncodedLen(12) + 1 + base64.RawURLEncoding.EncodedLen(plaintext+16)
	}
	require.Equal(t, maxMKEnvelopeChars, envelopeChars(maxMKPlaintextBytes))
	require.Greater(t, envelopeChars(maxMKPlaintextBytes+1), maxMKEnvelopeChars)

	dek := fixtureBytes(t, f.MK.DEK)
	context := mkContext{f.MK.Context["api_origin"], f.MK.Context["user_id"], f.MK.Context["dek_id"]}
	head := mkEnvelopePrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 12)) + "."
	// Well-formed base64 of zeros: at the limit it reaches decryption, one past it is refused first.
	_, err := openMK(head+strings.Repeat("A", maxMKEnvelopeChars-len(head)), dek, context)
	require.Error(t, err)
	require.NotErrorIs(t, err, errMKFormat)
	_, err = openMK(head+strings.Repeat("A", maxMKEnvelopeChars-len(head)+1), dek, context)
	require.ErrorIs(t, err, errMKFormat)
}

func TestOwnerContractSignedRequestsMatchFixtureBytes(t *testing.T) {
	f := loadOwnerContract(t).OwnerRequest
	private := ed25519.NewKeyFromSeed(fixtureBytes(t, f.Seed))
	keySigner, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: private}))
	agentSigners, err := keyring.Signers()
	require.NoError(t, err)
	owner, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f.Owner, "ed25519:"))
	require.NoError(t, err)
	for _, fixture := range f.Requests {
		var request ownerRequest
		require.NoError(t, decodeCanonical([]byte(fixture.Bytes), &request), fixture.Name)
		require.Equal(t, fixture.InnerBody, string(fixtureBytes(t, request.Body)), fixture.Name)
		for _, signer := range []ssh.Signer{keySigner, agentSigners[0]} {
			envelope, err := signOwnerRequest(signer, request)
			require.NoError(t, err, fixture.Name)
			require.Equal(t, fixture.Envelope, string(envelope), fixture.Name)
		}
		require.True(t, ed25519.Verify(owner, []byte(ownerRequestContext+fixture.Bytes), fixtureBytes(t, fixture.Signature)), fixture.Name)
	}
	for _, invalid := range f.InvalidRequests {
		var request ownerRequest
		require.NoError(t, decodeCanonical([]byte(invalid.Bytes), &request), invalid.Case)
		_, err := signOwnerRequest(keySigner, request)
		require.Error(t, err, invalid.Case)
	}
	var request ownerRequest
	require.NoError(t, decodeCanonical([]byte(f.Requests[0].Bytes), &request))
	otherSigner, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	require.NoError(t, err)
	_, err = signOwnerRequest(otherSigner, request)
	require.Error(t, err, "the owner field must name the signing key")
	// Only the invalid_signature cases fail verification against the measured owner key.
	for _, reject := range f.ServerRejects {
		measured, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(reject.Server["owner"].(string), "ed25519:"))
		require.NoError(t, err)
		valid := ed25519.Verify(measured, []byte(ownerRequestContext+reject.Bytes), fixtureBytes(t, reject.Signature))
		require.Equal(t, reject.Error == nil || *reject.Error != "invalid_signature", valid, reject.Case)
	}
}

func TestOwnerContractKeySyncCodeAndEnvelope(t *testing.T) {
	f := loadOwnerContract(t).KeySync
	targets, request := f.Targets.targets(), f.Request.request(t)
	require.Equal(t, f.LaunchURL, keySyncLaunchURL(request, targets))
	require.Equal(t, f.Canonical, string(canonicalKeySyncRequest(request, targets)))
	require.Equal(t, f.Code, confirmationCode([]byte(f.Canonical)))
	for _, input := range f.CodeInputs {
		require.Equal(t, input.Matches, confirmationCodeMatches(input.Input, f.Code), input.Input)
	}

	private, err := ecdh.X25519().NewPrivateKey(fixtureBytes(t, f.RecipientKey))
	require.NoError(t, err)
	require.Equal(t, request.HPKEPublicKey, private.PublicKey().Bytes())
	require.Len(t, f.Payloads, 2)
	for _, payload := range f.Payloads {
		envelope, err := openKeySyncEnvelope(private, request, targets, payload.Payload)
		require.NoError(t, err, payload.SealedBy)
		plain, err := contractJSON(envelope)
		require.NoError(t, err)
		require.Equal(t, f.EnvelopePlaintext, string(plain), payload.SealedBy)
	}
	for _, changed := range f.ChangedContexts {
		changedTargets, changedRequest := changed.Targets.targets(), changed.Request.request(t)
		code := confirmationCode(canonicalKeySyncRequest(changedRequest, changedTargets))
		require.Equal(t, changed.Code, code, changed.Case)
		require.NotEqual(t, f.Code, code, changed.Case)
		_, err := openKeySyncEnvelope(private, changedRequest, changedTargets, f.Payloads[0].Payload)
		require.Error(t, err, changed.Case)
	}

	for _, reject := range f.PayloadRejects {
		_, err := openKeySyncEnvelope(private, reject.Request.request(t), targets, reject.Payload)
		require.Error(t, err, reject.Case)
	}
	// Well-formed base64 at the limit reaches HPKE; one past it is refused before decoding.
	_, err = openKeySyncEnvelope(private, request, targets, strings.Repeat("A", maxKeySyncPayloadChars))
	require.ErrorContains(t, err, "not sealed for this request")
	_, err = openKeySyncEnvelope(private, request, targets, strings.Repeat("A", maxKeySyncPayloadChars+1))
	require.ErrorContains(t, err, "malformed key-sync callback")

	var envelope keySyncEnvelope
	require.NoError(t, decodeCanonical([]byte(f.EnvelopePlaintext), &envelope))
	require.Equal(t, f.CompletionURL, keySyncCompletionURL(targets, request.Request, envelope.UserID, "org_2fixtureB"))
}

func TestOwnerContractSandboxEHBPKey(t *testing.T) {
	f := loadOwnerContract(t).SandboxEHBPKey
	raw, err := sandboxEHBPKey(f.SPKIHex)
	require.NoError(t, err)
	require.Equal(t, f.RawHex, hex.EncodeToString(raw))
	for _, reject := range f.Reject {
		_, err := sandboxEHBPKey(reject.SPKIHex)
		require.Error(t, err, reject.Case)
	}
}
