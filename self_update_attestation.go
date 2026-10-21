package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/golang/snappy"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Self-update artifacts are verified against Sigstore attestations produced by
// the release workflow, not just the checksum file shipped in the same
// release: the checksum travels over the same TLS connection as the archive,
// so on its own it only rules out corruption, not an attacker who controls the
// network path. Attestations add two properties the checksum cannot provide:
// the signing identity is pinned to this repository's release workflow, and
// the attestation is fetched from api.github.com, an origin independent of the
// release CDN, so serving a forged archive requires breaking TLS to two
// independent origins and forging a Sigstore certificate chain rooted in the
// embedded trust root.

const (
	attestationsBaseURL = "https://api.github.com/repos/tinfoilsh/tinfoil-cli/attestations"
	attestationsLimit   = 4 << 20
	attestationOIDC     = "https://token.actions.githubusercontent.com"
)

//go:embed trusted_root_sigstore.json
var updateTrustedRoot []byte

// attestationEnvelope is the GitHub API response for the attestations of one
// digest: a list of bundles, each served snappy-compressed from a short-lived
// URL in Azure blob storage.
type attestationEnvelope struct {
	Attestations []struct {
		BundleURL string `json:"bundle_url"`
	} `json:"attestations"`
}

// verifyUpdateAttestation checks that a Sigstore attestation exists for the
// downloaded archive, that it verifies against the embedded trust root, and
// that its signing certificate is this repository's release workflow run from
// the expected tag. Every check is mandatory; there is no fallback to
// checksum-only updates. The attestations endpoint is normally the GitHub
// API; callers pass it so tests can serve their own listing.
func verifyUpdateAttestation(ctx context.Context, client *http.Client, archive []byte, tag string, endpointBase string) error {
	digest := sha256.Sum256(archive)
	endpoint := endpointBase + "/sha256:" + hex.EncodeToString(digest[:])
	data, err := fetchUpdateData(ctx, client, endpoint, version, attestationsLimit)
	if err != nil {
		return fmt.Errorf("fetching attestations: %w", err)
	}
	var envelope attestationEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decoding attestation list: %w", err)
	}
	if len(envelope.Attestations) == 0 {
		return errors.New("release has no attestations; refusing to install")
	}

	// The signer workflow must be this repository's release workflow, run
	// from the tag being installed — not a draft, another repository, or a
	// branch push.
	expectedSAN := fmt.Sprintf(`^https://github\.com/tinfoilsh/tinfoil-cli/\.github/workflows/release\.yml@refs/tags/%s$`, regexp.QuoteMeta(tag))
	var lastErr error
	for _, att := range envelope.Attestations {
		ok, err := verifyOneAttestation(ctx, client, att.BundleURL, digest, expectedSAN)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			return nil
		}
	}
	if lastErr != nil {
		return fmt.Errorf("verifying update attestations: %w", lastErr)
	}
	return errors.New("no valid attestation matches this archive; refusing to install")
}

// verifyOneAttestation fetches one bundle and verifies it end to end. It
// returns (true, nil) when the bundle authenticates the archive and (false,
// err) when it does not.
func verifyOneAttestation(ctx context.Context, client *http.Client, bundleURL string, digest [sha256.Size]byte, expectedSAN string) (bool, error) {
	if !strings.HasPrefix(bundleURL, "https://") {
		return false, errors.New("attestation bundle URL is not HTTPS")
	}
	compressed, err := fetchUpdateData(ctx, client, bundleURL, version, attestationsLimit)
	if err != nil {
		return false, fmt.Errorf("fetching attestation bundle: %w", err)
	}
	bundleJSON, err := snappy.Decode(nil, compressed)
	if err != nil {
		return false, fmt.Errorf("attestation bundle is not valid snappy data: %w", err)
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return false, fmt.Errorf("parsing attestation bundle: %w", err)
	}
	// Only the v0.3 single-certificate layout is accepted, matching the
	// SDKs: the legacy x509CertificateChain layout can carry extra CA
	// certificates under the signing certificate.
	if b.GetVerificationMaterial().GetX509CertificateChain() != nil {
		return false, errors.New("legacy bundle format not supported")
	}
	env := b.GetDsseEnvelope()
	if env == nil || len(env.GetSignatures()) != 1 {
		return false, errors.New("attestation bundle must carry exactly one DSSE signature")
	}

	trustRoot, err := root.NewTrustedRootFromJSON(updateTrustedRoot)
	if err != nil {
		return false, fmt.Errorf("loading embedded trust root: %w", err)
	}
	verifier, err := verify.NewSignedEntityVerifier(
		trustRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return false, fmt.Errorf("creating verifier: %w", err)
	}

	sanMatcher, err := verify.NewSANMatcher("", expectedSAN)
	if err != nil {
		return false, fmt.Errorf("creating SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(attestationOIDC, "")
	if err != nil {
		return false, fmt.Errorf("creating issuer matcher: %w", err)
	}
	// runner_environment comes from the OIDC token, so a workflow retargeted
	// to self-hosted (operator-controlled) infrastructure cannot claim
	// github-hosted.
	certID, err := verify.NewCertificateIdentity(
		sanMatcher,
		issuerMatcher,
		certificate.Extensions{RunnerEnvironment: "github-hosted"},
	)
	if err != nil {
		return false, fmt.Errorf("creating certificate identity: %w", err)
	}

	result, err := verifier.Verify(
		&b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest[:]),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return false, fmt.Errorf("attestation does not verify: %w", err)
	}
	// WithArtifactDigest matches the digest against any subject in the
	// statement, which is the right semantics here: the release workflow
	// attests every platform archive in one SLSA provenance statement, so
	// the downloaded archive's digest must appear among the subjects.
	if result == nil || result.Statement == nil || len(result.Statement.Subject) == 0 {
		return false, errors.New("verified attestation carries no in-toto subject")
	}
	return true, nil
}
