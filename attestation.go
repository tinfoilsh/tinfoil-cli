package main

import (
	"crypto/tls"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
}

var attestationCmd = &cobra.Command{
	Use:     "attestation",
	Aliases: []string{"att"},
	Short:   "Attestation commands",
}

func tlsConnection(enclaveHost string) (*tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", enclaveHost, &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("dialing enclave: %v", err)
	}
	cs := conn.ConnectionState()
	return &cs, nil
}

func newVerifiedClient(host, source, sealedTo string) (*client.SecureClient, error) {
	if host == "" {
		return nil, fmt.Errorf("--enclave is required")
	}
	if source == "" {
		return nil, fmt.Errorf("v3 verification requires an expected workload; pass --repo owner/name[@tag][@sha256:digest]")
	}
	var opts *client.VerificationOptions
	if sealedTo != "" {
		opts = &client.VerificationOptions{PinnedRegisters: &measurement.Measurement{
			Type:      measurement.TdxGuestV2,
			Registers: []string{"", "", "", "", sealedTo},
		}}
	}
	return client.NewSecureClient(host, source, opts)
}

type auditRecord struct {
	Timestamp string `json:"timestamp"`

	Enclave string `json:"enclave"`
	Repo    string `json:"repo,omitempty"`
	Digest  string `json:"digest,omitempty"`

	Measurements struct {
		Sigstore measurement.Measurement  `json:"sigstore,omitempty"` // Measurement from sigstore bundle
		Enclave  *measurement.Measurement `json:"enclave,omitempty"`  // Measurement from enclave attestation over HTTP
	} `json:"measurements"`

	Keys struct {
		Enclave    string `json:"enclave,omitempty"`    // Public key from enclave attestation over HTTP
		Connection string `json:"connection,omitempty"` // Public key from connection
	} `json:"keys"`

	CryptoMaterial     []envelope.CryptoMaterialItem `json:"crypto_material"`
	FreshnessExpiresAt time.Time                     `json:"freshness_expires_at"`

	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// verificationError returns an error when the audit record reports a
// verification failure, so callers can exit non-zero.
func (r *auditRecord) verificationError() error {
	if r.Status == "ok" {
		return nil
	}
	return fmt.Errorf("verification failed: %s", r.Error)
}

func verifyAttestation(l *log.Logger) (*auditRecord, error) {
	host, source := enclaveHost, repo
	if host == "" {
		router, err := client.NewDefaultClient(nil)
		if err != nil {
			return nil, fmt.Errorf("getting router: %w", err)
		}
		host = router.Enclave()
		if source == "" {
			source = router.Repo()
		}
		l.Printf("Using auto selected router: %s", host)
	}
	secure, err := newVerifiedClient(host, source, "")
	if err != nil {
		return nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}

	record := &auditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Enclave: host, Repo: source, Digest: verified.CodeDigest,
		CryptoMaterial: verified.CryptoMaterial, FreshnessExpiresAt: verified.FreshnessExpiresAt,
	}
	record.Measurements.Sigstore = *verified.CodeMeasurement
	record.Measurements.Enclave = verified.EnclaveMeasurement
	record.Keys.Enclave, err = verified.TLSPublicKeyFP()
	if err != nil {
		return nil, err
	}

	// Get remote pubkey fingerprint
	cs, err := tlsConnection(host + ":443")
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %w", err)
	}
	record.Keys.Connection, err = client.ConnectionCertFP(*cs)
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %w", err)
	}

	if record.Keys.Connection != record.Keys.Enclave {
		record.Status, record.Error = "fail", "remote public key does not match the endorsed TLS key"
	} else {
		record.Status = "ok"
		l.Printf("Verified %s at %s; TLS key %s", source, verified.CodeDigest, record.Keys.Enclave)
	}
	return record, nil
}
