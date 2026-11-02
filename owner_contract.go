package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	mkEnvelopePrefix       = "mk1."
	mkAADLabel             = "tinfoil-mk-v1"
	maxMKEnvelopeChars     = 262144
	maxMKPlaintextBytes    = 196576
	maxMKResources         = 256
	maxBucketChars         = 512
	maxKeySyncPayloadChars = 8192
	maxSafeInteger         = 1<<53 - 1
	ownerRequestContext    = "tinfoil owner request v3\x00"
	ownerNonceBytes        = 24
	keySyncRequestLabel    = "tinfoil-cli-key-sync-v1"
	keySyncConfirmLabel    = "tinfoil-cli-confirm-v1"
	keySyncEnvelopeLabel   = "tinfoil-cli-key-sync-envelope-v1\x00"
	confirmationAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
)

var (
	userIDPattern  = regexp.MustCompile(`^user_[A-Za-z0-9]{1,64}$`)
	accountPattern = regexp.MustCompile(`^(personal|org_[A-Za-z0-9]{1,64})$`)
	errMKFormat    = errors.New("the encrypted key bundle is damaged or uses an unsupported format")
)

type b64u []byte

func (b b64u) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *b64u) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	decoded, err := decodeB64U(text, -1)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// decodeB64U requires the canonical encoding; Go's decoder alone skips CR and LF.
func decodeB64U(text string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != text || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func validID16(id string) bool {
	_, err := decodeB64U(id, 16)
	return err == nil
}

func printableASCII(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

func validLowerUUID(id string) bool { return looksLikeUUID(id) && id == strings.ToLower(id) }

func contractJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func decodeCanonical(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	if canonical, err := contractJSON(v); err != nil || !bytes.Equal(canonical, data) {
		return errors.New("not in canonical form")
	}
	return nil
}

func ownerKeyString(public ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(public)
}

func ed25519PublicKeyString(seed []byte) string {
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	return ownerKeyString(private.Public().(ed25519.PublicKey))
}

type mkBinding struct {
	Account     string  `json:"account"`
	ContainerID string  `json:"container_id"`
	InstanceID  *string `json:"instance_id"`
	VolumeID    *string `json:"volume_id"`
	Bucket      *string `json:"bucket"`
}

type mkResource struct {
	KeyID               string     `json:"key_id"`
	Kind                string     `json:"kind"`
	AttemptID           string     `json:"attempt_id"`
	OwnerSeed           b64u       `json:"owner_seed"`
	OwnerPublicKey      string     `json:"owner_public_key"`
	StorageKey          b64u       `json:"storage_key"`
	MonitorIdentitySeed b64u       `json:"monitor_identity_seed"`
	MinGeneration       *uint64    `json:"min_generation"`
	Binding             *mkBinding `json:"binding"`
}

type mkPayload struct {
	Version   int          `json:"version"`
	Resources []mkResource `json:"resources"`
}

func (r *mkResource) validate() error {
	sandbox := r.Kind == "sandbox"
	if !validID16(r.KeyID) || !validID16(r.AttemptID) || (!sandbox && r.Kind != "monitor") ||
		len(r.OwnerSeed) != ed25519.SeedSize || len(r.StorageKey) != 32 ||
		r.OwnerPublicKey != ed25519PublicKeyString(r.OwnerSeed) ||
		sandbox != (len(r.MonitorIdentitySeed) == ed25519.SeedSize) || (!sandbox && r.MonitorIdentitySeed != nil) ||
		sandbox != (r.MinGeneration == nil) || (r.MinGeneration != nil && *r.MinGeneration > maxSafeInteger) {
		return fmt.Errorf("key %q is invalid", r.KeyID)
	}
	if b := r.Binding; b != nil {
		valid := accountPattern.MatchString(b.Account) && validLowerUUID(b.ContainerID)
		if sandbox {
			valid = valid && b.InstanceID != nil && validLowerUUID(*b.InstanceID) && b.VolumeID != nil && validLowerUUID(*b.VolumeID) && b.Bucket == nil
		} else {
			valid = valid && b.InstanceID == nil && b.VolumeID == nil && b.Bucket != nil && len(*b.Bucket) <= maxBucketChars && printableASCII(*b.Bucket)
		}
		if !valid {
			return fmt.Errorf("key %q has an invalid resource binding", r.KeyID)
		}
	}
	return nil
}

func (p *mkPayload) validate() error {
	if p.Version != 1 || p.Resources == nil || len(p.Resources) > maxMKResources {
		return errMKFormat
	}
	owners := map[string]bool{}
	for i := range p.Resources {
		r := &p.Resources[i]
		if err := r.validate(); err != nil {
			return err
		}
		if (i > 0 && p.Resources[i-1].KeyID >= r.KeyID) || owners[r.OwnerPublicKey] {
			return errMKFormat
		}
		owners[r.OwnerPublicKey] = true
	}
	return nil
}

type mkContext struct{ APIOrigin, UserID, DEKID string }

func contractAAD(fields ...string) ([]byte, error) {
	for _, field := range fields {
		if !printableASCII(field) {
			return nil, errors.New("invalid authenticated context")
		}
	}
	return []byte(strings.Join(fields, "\x00")), nil
}

func (c mkContext) aad() ([]byte, error) {
	if !userIDPattern.MatchString(c.UserID) || !validID16(c.DEKID) {
		return nil, errors.New("invalid key bundle context")
	}
	return contractAAD(mkAADLabel, c.APIOrigin, c.UserID, c.DEKID)
}

func mkBlock(dek []byte) (cipher.Block, error) {
	if len(dek) != 32 {
		return nil, errors.New("the data encryption key must be 32 bytes")
	}
	return aes.NewCipher(dek)
}

func sealMK(payload *mkPayload, dek []byte, c mkContext) (string, error) {
	if err := payload.validate(); err != nil {
		return "", err
	}
	aad, err := c.aad()
	if err != nil {
		return "", err
	}
	plain, err := contractJSON(payload)
	if err != nil || len(plain) > maxMKPlaintextBytes {
		return "", errors.Join(errors.New("the key bundle is too large"), err)
	}
	defer clear(plain)
	block, err := mkBlock(dek)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nil, plain, aad)
	return mkEnvelopePrefix + base64.RawURLEncoding.EncodeToString(sealed[:12]) + "." + base64.RawURLEncoding.EncodeToString(sealed[12:]), nil
}

func openMK(envelope string, dek []byte, c mkContext) (*mkPayload, error) {
	aad, err := c.aad()
	if err != nil {
		return nil, err
	}
	block, err := mkBlock(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encodedNonce, encodedCiphertext, ok := strings.Cut(strings.TrimPrefix(envelope, mkEnvelopePrefix), ".")
	if len(envelope) > maxMKEnvelopeChars || !strings.HasPrefix(envelope, mkEnvelopePrefix) || !ok {
		return nil, errMKFormat
	}
	nonce, nonceErr := decodeB64U(encodedNonce, aead.NonceSize())
	ciphertext, ciphertextErr := decodeB64U(encodedCiphertext, -1)
	if nonceErr != nil || ciphertextErr != nil {
		return nil, errMKFormat
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("this key does not open the key bundle for this account")
	}
	defer clear(plain)
	var payload mkPayload
	if err := decodeCanonical(plain, &payload); err != nil {
		return nil, errMKFormat
	}
	if err := payload.validate(); err != nil {
		return nil, err
	}
	return &payload, nil
}

type ownerRequest struct {
	Protocol   string `json:"protocol"`
	Owner      string `json:"owner"`
	Resource   string `json:"resource"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Body       string `json:"body"`
	Operation  string `json:"operation"`
	Session    string `json:"session"`
	Generation uint64 `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	Nonce      string `json:"nonce"`
}

type ownerEnvelope struct {
	Request   b64u `json:"request"`
	Signature b64u `json:"signature"`
}

func ownerRequestMessage(request []byte) []byte {
	digest := sha256.Sum256(request)
	return append([]byte(ownerRequestContext), digest[:]...)
}

func signOwnerRequest(signer ssh.Signer, request ownerRequest) ([]byte, error) {
	var owner string
	if public, err := ssh.ParsePublicKey(signer.PublicKey().Marshal()); err == nil {
		if crypto, ok := public.(ssh.CryptoPublicKey); ok {
			if key, ok := crypto.CryptoPublicKey().(ed25519.PublicKey); ok {
				owner = ownerKeyString(key)
			}
		}
	}
	_, nonceErr := decodeB64U(request.Nonce, ownerNonceBytes)
	_, bodyErr := decodeB64U(request.Body, -1)
	if owner == "" || request.Owner != owner || nonceErr != nil || bodyErr != nil ||
		!validID16(request.Operation) || (request.Session != "" && !validID16(request.Session)) ||
		!strings.HasPrefix(request.Path, "/") || !printableASCII(request.Path) ||
		request.IssuedAt < 0 || request.IssuedAt > maxSafeInteger || request.Generation > maxSafeInteger {
		return nil, errors.New("invalid owner request")
	}
	raw, err := contractJSON(request)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, ownerRequestMessage(raw))
	if err != nil {
		return nil, err
	}
	if signature.Format != ssh.KeyAlgoED25519 || len(signature.Blob) != ed25519.SignatureSize {
		return nil, errors.New("the owner key did not produce an Ed25519 signature")
	}
	return contractJSON(ownerEnvelope{Request: raw, Signature: signature.Blob})
}

type keySyncRequest struct {
	HPKEPublicKey []byte
	Request       string
	UserID        string
	Account       string
	Expires       int64
}

type keySyncTargets struct {
	Terminal, APIOrigin, Callback, Completion string
}

func (r keySyncRequest) fields() [][2]string {
	return [][2]string{
		{"hpke_pubkey", base64.RawURLEncoding.EncodeToString(r.HPKEPublicKey)},
		{"request", r.Request},
		{"user", r.UserID},
		{"account", r.Account},
		{"expires", strconv.FormatInt(r.Expires, 10)},
	}
}

func keySyncLaunchURL(r keySyncRequest, t keySyncTargets) string {
	parts := []string{"v=1"}
	for _, field := range r.fields() {
		parts = append(parts, field[0]+"="+url.QueryEscape(field[1]))
	}
	return t.Terminal + "/cli#" + strings.Join(parts, "&")
}

func canonicalKeySyncRequest(r keySyncRequest, t keySyncTargets) []byte {
	lines := []string{keySyncRequestLabel}
	for _, field := range append(r.fields(), [][2]string{
		{"api_origin", t.APIOrigin}, {"callback", t.Callback}, {"completion", t.Completion},
	}...) {
		lines = append(lines, field[0]+"="+field[1])
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func confirmationCode(canonical []byte) string {
	digest := sha256.Sum256(append([]byte(keySyncConfirmLabel), canonical...))
	value := binary.BigEndian.Uint64(digest[:8]) % (24 * 24 * 24 * 24 * 24 * 24)
	code := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		code[i] = confirmationAlphabet[value%24]
		value /= 24
	}
	return string(code[:3]) + "-" + string(code[3:])
}

type keySyncEnvelope struct {
	V       int    `json:"v"`
	Request string `json:"request"`
	UserID  string `json:"user_id"`
	Expires int64  `json:"expires"`
	DEKID   string `json:"dek_id"`
	DEK     b64u   `json:"dek"`
}

var keySyncSuite = struct {
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.HKDFSHA256(), hpke.AES256GCM()}

func keySyncEnvelopeInfo(canonical []byte) []byte {
	digest := sha256.Sum256(canonical)
	return append([]byte(keySyncEnvelopeLabel), digest[:]...)
}

func openKeySyncEnvelope(private *ecdh.PrivateKey, r keySyncRequest, t keySyncTargets, payload string) (*keySyncEnvelope, error) {
	if len(payload) > maxKeySyncPayloadChars {
		return nil, errors.New("malformed key-sync callback")
	}
	sealed, err := decodeB64U(payload, -1)
	if err != nil {
		return nil, errors.New("malformed key-sync callback")
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		return nil, err
	}
	plain, err := hpke.Open(key, keySyncSuite.kdf, keySyncSuite.aead, keySyncEnvelopeInfo(canonicalKeySyncRequest(r, t)), sealed)
	if err != nil {
		return nil, errors.New("the key-sync callback was not sealed for this request")
	}
	defer clear(plain)
	var envelope keySyncEnvelope
	err = decodeCanonical(plain, &envelope)
	if err != nil || envelope.V != 1 || envelope.Request != r.Request || envelope.Expires != r.Expires ||
		!userIDPattern.MatchString(envelope.UserID) || envelope.UserID != r.UserID ||
		len(envelope.DEK) != 32 || !validID16(envelope.DEKID) {
		clear(envelope.DEK)
		return nil, errors.New("the key-sync callback does not match this request")
	}
	return &envelope, nil
}

func keySyncCompletionURL(t keySyncTargets, request, userID, account string) string {
	return t.Completion + "#v=1&request=" + url.QueryEscape(request) + "&user=" + url.QueryEscape(userID) + "&account=" + url.QueryEscape(account)
}
