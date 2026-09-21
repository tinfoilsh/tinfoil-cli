package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func init() { rootCmd.AddCommand(attestationCmd) }

var attestationCmd = &cobra.Command{
	Use: "attestation", Aliases: []string{"att"}, Short: "Attestation commands",
}

func tlsConnection(host string) (*tls.ConnectionState, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", host, &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("dialing enclave: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

// verificationOptions retains the ordinary v3 policy and adds an owner pin when
// the caller has a sandbox disk key. This pin cannot replace code provenance.
func verificationOptions(sealedTo string) (*client.VerificationOptions, error) {
	if sealedTo == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(sealedTo)
	if err != nil || len(decoded) != 48 {
		return nil, fmt.Errorf("--sealed-to must be a 48-byte RTMR3 value encoded as hex")
	}
	return &client.VerificationOptions{PinnedRegisters: &measurement.Measurement{
		Type:      measurement.TdxGuestV2,
		Registers: []string{"", "", "", "", strings.ToLower(sealedTo)},
	}}, nil
}

func newVerifiedClient(host, source, sealedTo string) (*client.SecureClient, error) {
	if host == "" {
		return nil, fmt.Errorf("--host is required")
	}
	if source == "" {
		return nil, fmt.Errorf("v3 verification requires an expected workload; pass --repo owner/name[@tag][@sha256:digest]")
	}
	opts, err := verificationOptions(sealedTo)
	if err != nil {
		return nil, err
	}
	source, err = expectedRepository(source)
	if err != nil {
		return nil, err
	}
	return client.NewSecureClient(host, source, opts)
}

type auditRecord struct {
	Timestamp    string `json:"timestamp"`
	Enclave      string `json:"enclave"`
	Repo         string `json:"repo,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Measurements struct {
		Sigstore measurement.Measurement  `json:"sigstore,omitempty"`
		Enclave  *measurement.Measurement `json:"enclave,omitempty"`
	} `json:"measurements"`
	Keys struct {
		Enclave    string `json:"enclave,omitempty"`
		Connection string `json:"connection,omitempty"`
	} `json:"keys"`
	CryptoMaterial     []envelope.CryptoMaterialItem `json:"crypto_material"`
	FreshnessExpiresAt time.Time                     `json:"freshness_expires_at"`
	Status             string                        `json:"status"`
	Error              string                        `json:"error,omitempty"`
}

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
	if source == "" {
		return nil, fmt.Errorf("v3 verification requires --repo for an explicit --host")
	}
	source, err := expectedRepository(source)
	if err != nil {
		return nil, err
	}
	// Retain the caller nonce for the audit record. Never obtain the expected
	// nonce or trusted repository from the document being verified.
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, err
	}
	document, err := envelope.Fetch(host, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetching v3 attestation: %w", err)
	}
	verified, err := client.VerifyDocumentV3(document, nonce, source, nil)
	if err != nil {
		return nil, fmt.Errorf("verifying v3 attestation: %w", err)
	}
	record := &auditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Enclave: host, Repo: source,
		Digest: verified.CodeDigest, Nonce: hex.EncodeToString(nonce),
		CryptoMaterial: verified.CryptoMaterial, FreshnessExpiresAt: verified.FreshnessExpiresAt,
	}
	record.Measurements.Sigstore = *verified.CodeMeasurement
	record.Measurements.Enclave = verified.EnclaveMeasurement
	record.Keys.Enclave, err = verified.TLSPublicKeyFP()
	if err != nil {
		return nil, err
	}
	address := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		address = net.JoinHostPort(host, "443")
	}
	state, err := tlsConnection(address)
	if err != nil {
		return nil, err
	}
	record.Keys.Connection, err = client.ConnectionCertFP(*state)
	if err != nil {
		return nil, err
	}
	switch {
	case !time.Now().Before(verified.FreshnessExpiresAt):
		record.Status, record.Error = "fail", "attestation freshness expired before channel binding"
	case record.Keys.Connection != record.Keys.Enclave:
		record.Status, record.Error = "fail", "remote public key does not match the endorsed TLS key"
	default:
		record.Status = "ok"
		l.Printf("Verified %s at %s; TLS key %s", source, verified.CodeDigest, record.Keys.Enclave)
	}
	return record, nil
}
