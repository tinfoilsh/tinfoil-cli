package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
)

// The fixture is the real attestation bundle GitHub serves for the published
// v0.19.9 linux/amd64 archive, captured snappy-compressed exactly as the
// attestations API returns it. Its subject[0] digest is pinned in the test so
// no network access is needed to exercise the verification path.
const fixtureSubjectDigest = "6c9bbaf8e7dc4cf1502cfa222cf8badf53386157dd8b433ac2855c4650babb77"

//go:embed testdata/attestation/bundle.snappy
var fixtureBundleSnappy []byte

// attestationsFixtureServer serves the GitHub attestations API shape for one
// digest: a list whose bundle_url points back at the same server.
func attestationsFixtureServer(t *testing.T, digest string, bundle []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sha256:"+digest:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(attestationEnvelope{Attestations: []struct {
				BundleURL string `json:"bundle_url"`
			}{{BundleURL: "https://" + r.Host + "/bundle"}}})
		case r.URL.Path == "/bundle":
			w.Header().Set("Content-Type", "application/x-snappy")
			_, _ = w.Write(bundle)
		default:
			// Any other digest: GitHub serves an empty listing.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(attestationEnvelope{})
		}
	}))
	return server
}

func fixtureArchiveDigest(t *testing.T) [sha256.Size]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "attestation", "archive.sha256"))
	require.NoError(t, err)
	var digest [sha256.Size]byte
	raw, err := hex.DecodeString(string(data))
	require.NoError(t, err)
	copy(digest[:], raw)
	return digest
}

// TestVerifyUpdateAttestationWalksListingToBundle proves the envelope walk
// dispatches from the listing to the bundle URL the listing names: a server
// that lists a bundle for any digest gets as far as bundle verification, which
// then fails on the digest mismatch.
func TestVerifyUpdateAttestationWalksListingToBundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/bundle":
			w.Header().Set("Content-Type", "application/x-snappy")
			_, _ = w.Write(fixtureBundleSnappy)
		default:
			// Listing for any digest: point at this server's bundle.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(attestationEnvelope{Attestations: []struct {
				BundleURL string `json:"bundle_url"`
			}{{BundleURL: "https://" + r.Host + "/bundle"}}})
		}
	}))
	defer server.Close()

	archive := []byte("not the attested archive")
	err := verifyUpdateAttestation(context.Background(), server.Client(), archive, "v0.19.9", server.URL)
	require.Error(t, err)
	// The walk reached the bundle and its subjects; the mismatch is the
	// digest, not the transport.
	require.Contains(t, err.Error(), "attestation does not verify")
}

// TestVerifyUpdateAttestationFailsClosedOnMissingListing proves a digest with
// no attestation listing is refused.
func TestVerifyUpdateAttestationFailsClosedOnMissingListing(t *testing.T) {
	digest := fixtureArchiveDigest(t)
	server := attestationsFixtureServer(t, hex.EncodeToString(digest[:]), fixtureBundleSnappy)
	defer server.Close()

	archive := []byte("an unattested archive")
	err := verifyUpdateAttestation(context.Background(), server.Client(), archive, "v0.19.9", server.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestations")
}

// TestVerifyOneAttestationVerifiesRealBundle checks the bundle directly, so
// the real archive digest is used end to end.
func TestVerifyOneAttestationVerifiesRealBundle(t *testing.T) {
	digest := fixtureArchiveDigest(t)
	expectedSAN := `^https://github\.com/tinfoilsh/tinfoil-cli/\.github/workflows/release\.yml@refs/tags/v0\.19\.9$`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixtureBundleSnappy)
	}))
	defer server.Close()

	ok, err := verifyOneAttestation(context.Background(), server.Client(), server.URL, digest, expectedSAN)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerifyOneAttestationRejectsWrongTag(t *testing.T) {
	digest := fixtureArchiveDigest(t)
	// The signer ran from v0.19.9; expecting any other tag must fail.
	expectedSAN := `^https://github\.com/tinfoilsh/tinfoil-cli/\.github/workflows/release\.yml@refs/tags/v0\.19\.10$`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixtureBundleSnappy)
	}))
	defer server.Close()

	ok, err := verifyOneAttestation(context.Background(), server.Client(), server.URL, digest, expectedSAN)
	require.Error(t, err)
	require.False(t, ok)
}

func TestVerifyOneAttestationRejectsTamperedBundle(t *testing.T) {
	digest := fixtureArchiveDigest(t)
	expectedSAN := `^https://github\.com/tinfoilsh/tinfoil-cli/\.github/workflows/release\.yml@refs/tags/v0\.19\.9$`

	// Corrupt one byte inside the decoded bundle, re-encode, and expect the
	// signature or transparency-log check to fail.
	decoded, err := snappy.Decode(nil, fixtureBundleSnappy)
	require.NoError(t, err)
	decoded[len(decoded)-8] ^= 0x01
	corrupted := snappy.Encode(nil, decoded)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(corrupted)
	}))
	defer server.Close()

	ok, verifyErr := verifyOneAttestation(context.Background(), server.Client(), server.URL, digest, expectedSAN)
	require.Error(t, verifyErr)
	require.False(t, ok)
}

func TestVerifyOneAttestationRejectsNonHTTPSBundleURL(t *testing.T) {
	digest := fixtureArchiveDigest(t)
	ok, err := verifyOneAttestation(context.Background(), http.DefaultClient, "http://example.test/bundle", digest, "x")
	require.Error(t, err)
	require.False(t, ok)
	require.Contains(t, err.Error(), "not HTTPS")
}

func TestVerifyOneAttestationRejectsWrongDigest(t *testing.T) {
	expectedSAN := `^https://github\.com/tinfoilsh/tinfoil-cli/\.github/workflows/release\.yml@refs/tags/v0\.19\.9$`
	digest := sha256.Sum256([]byte("not the released archive"))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixtureBundleSnappy)
	}))
	defer server.Close()

	ok, err := verifyOneAttestation(context.Background(), server.Client(), server.URL, digest, expectedSAN)
	require.Error(t, err)
	require.False(t, ok)
}

// TestSelfUpdateRefusesUpdateWhenAttestationFails proves the install path is
// fail-closed: an archive that passes its checksum but fails attestation is
// never installed.
func TestSelfUpdateRefusesUpdateWhenAttestationFails(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.u.verifyAttestation = func(context.Context, *http.Client, []byte, string) error {
		return fmt.Errorf("no valid attestation")
	}
	_, err := f.u.run(context.Background(), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing update without a valid release attestation")
	f.assertTarget(t, testOriginalCLI)
	require.Equal(t, 3, f.requestCount())
}

// TestSelfUpdateAttendsBeforeInstall proves attestation runs on the downloaded
// bytes and receives the release tag.
func TestSelfUpdateAttestationSeesArchiveAndTag(t *testing.T) {
	f := newSelfUpdateFixture(t)
	var seenTag string
	var seenLen int
	f.u.verifyAttestation = func(_ context.Context, _ *http.Client, archive []byte, tag string) error {
		seenTag = tag
		seenLen = len(archive)
		return nil
	}
	result, err := f.u.run(context.Background(), false)
	require.NoError(t, err)
	require.Equal(t, updateStatusInstalled, result.Status)
	require.Equal(t, "v"+testUpdateVersion, seenTag)
	require.Equal(t, len(f.archive), seenLen)
}
