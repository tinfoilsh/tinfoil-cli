package keybundle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
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
)

const (
	mkEnvelopePrefix       = "mk1."
	mkAADLabel             = "tinfoil-mk-v1"
	maxMKEnvelopeChars     = 262144
	maxMKPlaintextBytes    = 196576
	MaxResources           = 256
	MaxBucketChars         = 512
	MaxKeySyncPayloadChars = 8192
	MaxSafeInteger         = 1<<53 - 1
	keySyncRequestLabel    = "tinfoil-cli-key-sync-v1"
	keySyncConfirmLabel    = "tinfoil-cli-confirm-v1"
	keySyncEnvelopeLabel   = "tinfoil-cli-key-sync-envelope-v1\x00"
	confirmationAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
)

var (
	userIDPattern    = regexp.MustCompile(`^user_[A-Za-z0-9]{1,64}$`)
	accountPattern   = regexp.MustCompile(`^(personal|org_[A-Za-z0-9]{1,64})$`)
	lowerUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	errMKFormat      = errors.New("the encrypted key bundle is damaged or uses an unsupported format")
)

type Base64URL []byte

func (b Base64URL) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *Base64URL) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	decoded, err := DecodeBase64URL(text, -1)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// DecodeBase64URL requires the canonical encoding; Go's decoder alone skips CR and LF.
func DecodeBase64URL(text string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != text || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func ValidID16(id string) bool {
	_, err := DecodeBase64URL(id, 16)
	return err == nil
}

func printableASCII(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

func validLowerUUID(id string) bool { return lowerUUIDPattern.MatchString(id) }

func ValidUserID(id string) bool { return userIDPattern.MatchString(id) }

func ValidAccount(account string) bool { return accountPattern.MatchString(account) }

func Marshal(v any) ([]byte, error) {
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
	if canonical, err := Marshal(v); err != nil || !bytes.Equal(canonical, data) {
		return errors.New("not in canonical form")
	}
	return nil
}

func ownerKeyString(public ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(public)
}

func PublicKeyString(seed []byte) string {
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	return ownerKeyString(private.Public().(ed25519.PublicKey))
}

type Binding struct {
	Account     string  `json:"account"`
	ContainerID string  `json:"container_id"`
	InstanceID  *string `json:"instance_id"`
	VolumeID    *string `json:"volume_id"`
	Bucket      *string `json:"bucket"`
}

type Resource struct {
	KeyID               string    `json:"key_id"`
	Kind                string    `json:"kind"`
	AttemptID           string    `json:"attempt_id"`
	OwnerSeed           Base64URL `json:"owner_seed"`
	OwnerPublicKey      string    `json:"owner_public_key"`
	StorageKey          Base64URL `json:"storage_key"`
	MonitorIdentitySeed Base64URL `json:"monitor_identity_seed"`
	MinGeneration       *uint64   `json:"min_generation"`
	Binding             *Binding  `json:"binding"`
}

type Payload struct {
	Version   int        `json:"version"`
	Resources []Resource `json:"resources"`
}

func (r *Resource) validate() error {
	sandbox := r.Kind == "sandbox"
	if !ValidID16(r.KeyID) || !ValidID16(r.AttemptID) || (!sandbox && r.Kind != "monitor") ||
		len(r.OwnerSeed) != ed25519.SeedSize || len(r.StorageKey) != 32 ||
		r.OwnerPublicKey != PublicKeyString(r.OwnerSeed) ||
		sandbox != (len(r.MonitorIdentitySeed) == ed25519.SeedSize) || (!sandbox && r.MonitorIdentitySeed != nil) ||
		sandbox != (r.MinGeneration == nil) || (r.MinGeneration != nil && *r.MinGeneration > MaxSafeInteger) {
		return fmt.Errorf("key %q is invalid", r.KeyID)
	}
	if b := r.Binding; b != nil {
		valid := accountPattern.MatchString(b.Account) && validLowerUUID(b.ContainerID)
		if sandbox {
			valid = valid && b.InstanceID != nil && validLowerUUID(*b.InstanceID) && b.VolumeID != nil && validLowerUUID(*b.VolumeID) && b.Bucket == nil
		} else {
			valid = valid && b.InstanceID == nil && b.VolumeID == nil && (b.Bucket == nil || len(*b.Bucket) <= MaxBucketChars && printableASCII(*b.Bucket))
		}
		if !valid {
			return fmt.Errorf("key %q has an invalid resource binding", r.KeyID)
		}
	}
	return nil
}

func (p *Payload) validate() error {
	if p.Version != 1 || p.Resources == nil || len(p.Resources) > MaxResources {
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

type Context struct{ APIOrigin, UserID, DEKID string }

func contractAAD(fields ...string) ([]byte, error) {
	for _, field := range fields {
		if !printableASCII(field) {
			return nil, errors.New("invalid authenticated context")
		}
	}
	return []byte(strings.Join(fields, "\x00")), nil
}

func (c Context) aad() ([]byte, error) {
	if !userIDPattern.MatchString(c.UserID) || !ValidID16(c.DEKID) {
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

func Seal(payload *Payload, dek []byte, c Context) (string, error) {
	if err := payload.validate(); err != nil {
		return "", err
	}
	aad, err := c.aad()
	if err != nil {
		return "", err
	}
	plain, err := Marshal(payload)
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

func Open(envelope string, dek []byte, c Context) (*Payload, error) {
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
	nonce, nonceErr := DecodeBase64URL(encodedNonce, aead.NonceSize())
	ciphertext, ciphertextErr := DecodeBase64URL(encodedCiphertext, -1)
	if nonceErr != nil || ciphertextErr != nil {
		return nil, errMKFormat
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("this key does not open the key bundle for this account")
	}
	defer clear(plain)
	var payload Payload
	if err := decodeCanonical(plain, &payload); err != nil {
		return nil, errMKFormat
	}
	if err := payload.validate(); err != nil {
		return nil, err
	}
	return &payload, nil
}

type SyncRequest struct {
	HPKEPublicKey []byte
	Request       string
	UserID        string
	Account       string
	Expires       int64
}

type SyncTargets struct {
	Terminal, APIOrigin, Callback, Completion string
}

func (r SyncRequest) fields() [][2]string {
	return [][2]string{
		{"hpke_pubkey", base64.RawURLEncoding.EncodeToString(r.HPKEPublicKey)},
		{"request", r.Request},
		{"user", r.UserID},
		{"account", r.Account},
		{"expires", strconv.FormatInt(r.Expires, 10)},
	}
}

func LaunchURL(r SyncRequest, t SyncTargets) string {
	parts := []string{"v=1"}
	for _, field := range r.fields() {
		parts = append(parts, field[0]+"="+url.QueryEscape(field[1]))
	}
	return t.Terminal + "/cli#" + strings.Join(parts, "&")
}

func CanonicalRequest(r SyncRequest, t SyncTargets) []byte {
	lines := []string{keySyncRequestLabel}
	for _, field := range append(r.fields(), [][2]string{
		{"api_origin", t.APIOrigin}, {"callback", t.Callback}, {"completion", t.Completion},
	}...) {
		lines = append(lines, field[0]+"="+field[1])
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func ConfirmationCode(canonical []byte) string {
	digest := sha256.Sum256(append([]byte(keySyncConfirmLabel), canonical...))
	value := binary.BigEndian.Uint64(digest[:8]) % (24 * 24 * 24 * 24 * 24 * 24)
	code := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		code[i] = confirmationAlphabet[value%24]
		value /= 24
	}
	return string(code[:3]) + "-" + string(code[3:])
}

type SyncEnvelope struct {
	V       int       `json:"v"`
	Request string    `json:"request"`
	UserID  string    `json:"user_id"`
	Expires int64     `json:"expires"`
	DEKID   string    `json:"dek_id"`
	DEK     Base64URL `json:"dek"`
}

var keySyncSuite = struct {
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.HKDFSHA256(), hpke.AES256GCM()}

func keySyncEnvelopeInfo(canonical []byte) []byte {
	digest := sha256.Sum256(canonical)
	return append([]byte(keySyncEnvelopeLabel), digest[:]...)
}

func OpenSyncEnvelope(private *ecdh.PrivateKey, r SyncRequest, t SyncTargets, payload string) (*SyncEnvelope, error) {
	if len(payload) > MaxKeySyncPayloadChars {
		return nil, errors.New("malformed key-sync callback")
	}
	sealed, err := DecodeBase64URL(payload, -1)
	if err != nil {
		return nil, errors.New("malformed key-sync callback")
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		return nil, err
	}
	plain, err := hpke.Open(key, keySyncSuite.kdf, keySyncSuite.aead, keySyncEnvelopeInfo(CanonicalRequest(r, t)), sealed)
	if err != nil {
		return nil, errors.New("the key-sync callback was not sealed for this request")
	}
	defer clear(plain)
	var envelope SyncEnvelope
	err = decodeCanonical(plain, &envelope)
	if err != nil || envelope.V != 1 || envelope.Request != r.Request || envelope.Expires != r.Expires ||
		!userIDPattern.MatchString(envelope.UserID) || envelope.UserID != r.UserID ||
		len(envelope.DEK) != 32 || !ValidID16(envelope.DEKID) {
		clear(envelope.DEK)
		return nil, errors.New("the key-sync callback does not match this request")
	}
	return &envelope, nil
}

func CompletionURL(t SyncTargets, request, userID, account string) string {
	return t.Completion + "#v=1&request=" + url.QueryEscape(request) + "&user=" + url.QueryEscape(userID) + "&account=" + url.QueryEscape(account)
}
