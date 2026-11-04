package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
}

var attestationCmd = &cobra.Command{
	Use:     "attestation",
	Aliases: []string{"att"},
	Short:   "Verify enclave attestations",
}

func tlsConnection(enclaveHost string) (*tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", enclaveHost, &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("dialing enclave: %v", err)
	}
	cs := conn.ConnectionState()
	return &cs, nil
}

func verificationOptions(source, sealedTo string) (*tinfoil.EnclaveOptions, error) {
	var policy []verify.Option
	if localConfigFile != "" {
		if publicRegistry {
			return nil, fmt.Errorf("--public-registry and --config cannot be used together")
		}
		if source != "" {
			return nil, fmt.Errorf("--config and --repo cannot be used together")
		}
		data, err := readLocalConfig()
		if err != nil {
			return nil, err
		}
		policy = append(policy, verify.WithEmbeddedReferences(verify.EmbeddedReferences{Config: &verify.EmbeddedConfig{Bytes: data}}))
	} else if source == "" {
		return nil, fmt.Errorf("v3 verification requires an expected workload; pass --repo owner/name[@tag][@sha256:digest] or --config FILE")
	} else {
		var err error
		policy, err = registrySigningOptions(source)
		if err != nil {
			return nil, err
		}
	}
	if sealedTo != "" {
		pins, err := measurement.ParseExpectedTDX("", "", "", "", sealedTo)
		if err != nil {
			return nil, err
		}
		policy = append(policy, verify.WithPinnedRegisters(pins))
	}
	v, err := verify.NewVerifier(policy...)
	if err != nil {
		return nil, err
	}
	return &tinfoil.EnclaveOptions{Verifier: v}, nil
}

func newVerifiedClient(host, source, sealedTo string) (*tinfoil.EnclaveHTTPClient, error) {
	if host == "" {
		return nil, fmt.Errorf("--enclave is required")
	}
	opts, err := verificationOptions(source, sealedTo)
	if err != nil {
		return nil, err
	}
	opts.VerificationCheck = func(verified *verify.Verification) error {
		return checkVerifiedDeployment(host, source, verified)
	}
	return tinfoil.NewEnclaveHTTPClient(context.Background(), host, source, opts)
}

type auditRecord struct {
	Timestamp string `json:"timestamp"`

	Enclave string `json:"enclave"`
	Repo    string `json:"repo,omitempty"`
	Digest  string `json:"digest,omitempty"`

	Measurements struct {
		Sigstore auditMeasurement `json:"sigstore,omitempty"` // Measurement from sigstore bundle
		Enclave  auditMeasurement `json:"enclave,omitempty"`  // Measurement from enclave attestation over HTTP
	} `json:"measurements"`

	Keys struct {
		Enclave    string `json:"enclave,omitempty"`    // Public key from enclave attestation over HTTP
		Connection string `json:"connection,omitempty"` // Public key from connection
	} `json:"keys"`

	CryptoMaterial     []document.CryptoMaterialItem `json:"crypto_material"`
	FreshnessExpiresAt time.Time                     `json:"freshness_expires_at"`

	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type auditMeasurement struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

func measurementRecord(expected measurement.Expected) auditMeasurement {
	const (
		snpType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
		tdxType = "https://tinfoil.sh/predicate/tdx-guest/v2"
	)
	var result auditMeasurement
	var registers []*measurement.Register
	switch value := expected.(type) {
	case measurement.ExpectedSEVSNP:
		result.Type, registers = snpType, []*measurement.Register{value.Launch}
	case measurement.ExpectedTDX:
		result.Type, registers = tdxType, []*measurement.Register{value.MRTD, value.RTMR0, value.RTMR1, value.RTMR2, value.RTMR3}
	}
	for _, register := range registers {
		value := ""
		if register != nil {
			value = register.String()
		}
		result.Registers = append(result.Registers, value)
	}
	return result
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
	if host == "" && localConfigFile != "" {
		return nil, fmt.Errorf("--enclave is required with --config")
	}
	if host == "" {
		router, err := tinfoil.NewRouterHTTPClient(context.Background(), nil)
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
	verified, err := secure.EnsureVerified(context.Background())
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}

	record := &auditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Enclave: host, Repo: source, Digest: verified.CodeDigest(),
		CryptoMaterial: verified.CryptoMaterial(), FreshnessExpiresAt: verified.FreshnessExpiresAt(),
	}
	record.Measurements.Sigstore = measurementRecord(verified.CodeMeasurement())
	record.Measurements.Enclave = measurementRecord(verified.EnclaveMeasurement().Expected())
	var ok bool
	record.Keys.Enclave, ok = verified.TLSPublicKeyFP()
	if !ok {
		return nil, fmt.Errorf("attestation has no TLS public key fingerprint")
	}

	// Get remote pubkey fingerprint
	cs, err := tlsConnection(host + ":443")
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %w", err)
	}
	record.Keys.Connection, err = verify.ConnectionCertFP(*cs)
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %w", err)
	}

	if record.Keys.Connection != record.Keys.Enclave {
		record.Status, record.Error = "fail", "remote public key does not match the endorsed TLS key"
	} else {
		record.Status = "ok"
		l.Printf("Verified %s at %s; TLS key %s", source, verified.CodeDigest(), record.Keys.Enclave)
	}
	return record, nil
}
