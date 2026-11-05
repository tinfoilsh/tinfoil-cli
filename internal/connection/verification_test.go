package connection

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"golang.org/x/crypto/ssh"
)

func TestConfigSnapshotSurvivesCallerAndFileChanges(t *testing.T) {
	data := []byte("# Preserve exact bytes.\ncvm-version: 0.15.1-rc.1@sha256:" + strings.Repeat("a", sha256.Size*2) + "\n")
	digest := sha256.Sum256(data)
	path := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(path, data, 0600))
	config, err := ReadConfig(path)
	require.NoError(t, err)
	input, err := NewConfig(data)
	require.NoError(t, err)
	data[0] = '!'
	returned := config.Bytes()
	returned[0] = '!'
	require.NoError(t, os.WriteFile(path, []byte("different config"), 0600))
	for _, snapshot := range []*Config{config, input} {
		require.NoError(t, snapshot.CheckDigest(hex.EncodeToString(digest[:])))
		require.ErrorContains(t, snapshot.CheckDigest(strings.Repeat("b", sha256.Size*2)), "does not match")
		options, err := (Verification{Config: snapshot}).Options()
		require.NoError(t, err)
		require.True(t, options.Verifier.CallerAuthorizesConfig())
	}
}

func TestVerificationRejectsMissingOrConflictingExpectations(t *testing.T) {
	config, err := NewConfig([]byte("cvm-version: 0.15.1-rc.1@sha256:" + strings.Repeat("a", sha256.Size*2)))
	require.NoError(t, err)
	for _, input := range []Verification{
		{},
		{Config: config, Reference: "acme/app"},
		{Config: config, PublicRegistry: true},
		{Config: &Config{}},
		{Reference: "acme/app", RTMR3: "invalid"},
		{Reference: "acme/app", RegistryIDs: []string{"invalid"}},
	} {
		_, err := input.Options()
		require.Error(t, err)
	}
	_, err = NewConfig(nil)
	require.ErrorContains(t, err, "config must contain")
	_, err = NewConfig(make([]byte, configendorsement.MaxConfigSize+1))
	require.ErrorContains(t, err, "config must contain")
	_, err = NewClient(t.Context(), "", Verification{Reference: "acme/app"})
	require.ErrorContains(t, err, "--enclave is required")
}

func TestVerificationKeepsRegistryTrustExplicit(t *testing.T) {
	registryID := configendorsement.RegistryIDPrefix + strings.Repeat("a", 32)
	nonce := make([]byte, document.NonceSize)
	doc, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	require.NoError(t, err)
	for _, public := range []bool{false, true} {
		options, err := (Verification{Reference: "acme/app", RegistryIDs: []string{registryID}, PublicRegistry: public}).Options()
		require.NoError(t, err)
		_, err = options.Verifier.VerifyV3(doc, nonce, "acme/app")
		require.Error(t, err)
		if public {
			require.NotContains(t, err.Error(), "configured trust requires")
		} else {
			require.ErrorContains(t, err, "configured trust requires")
		}
	}
}

type testEvidence struct {
	keys []document.CryptoMaterialItem
}

func (v testEvidence) FreshnessExpiresAt() time.Time { return time.Time{} }
func (v testEvidence) CryptoMaterialData(id, format string) (string, bool) {
	return verify.CryptoMaterialData(v.keys, id, format)
}

func TestEndorsedHostKeyRequiresTheDeclaredSPKI(t *testing.T) {
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	der, err := x509.MarshalPKIXPublicKey(public)
	require.NoError(t, err)
	item := document.CryptoMaterialItem{ID: attestedHostKeyID, Format: document.KeySPKIV1Format, Data: hex.EncodeToString(der)}
	key, err := EndorsedHostKey("enclave.test", testEvidence{keys: []document.CryptoMaterialItem{item}})
	require.NoError(t, err)
	want, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	require.Equal(t, want.Marshal(), key.Marshal())
	for _, change := range []func(*document.CryptoMaterialItem){
		func(item *document.CryptoMaterialItem) { item.ID = "other-key" },
		func(item *document.CryptoMaterialItem) { item.Format = "other-format" },
		func(item *document.CryptoMaterialItem) { item.Data = "not hex" },
		func(item *document.CryptoMaterialItem) { item.Data = hex.EncodeToString([]byte("not SPKI")) },
	} {
		invalid := item
		change(&invalid)
		_, err := EndorsedHostKey("enclave.test", testEvidence{keys: []document.CryptoMaterialItem{invalid}})
		require.Error(t, err)
	}
}
