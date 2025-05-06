package main

import (
	"crypto/tls"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
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

func verifyAttestation() (map[string]any, error) {
	if enclaveHost == "" {
		return nil, fmt.Errorf("enclave host is required")
	}
	if repo == "" {
		return nil, fmt.Errorf("repo is required")
	}

	auditRecord := make(map[string]any)
	auditRecord["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	auditRecord["enclave"] = enclaveHost

	log.Printf("Fetching latest release for %s", repo)
	digest, err := github.FetchLatestDigest(repo)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %v", err)
	}
	auditRecord["repo"] = repo
	auditRecord["digest"] = digest

	log.Printf("Fetching sigstore bundle from %s for digest %s", repo, digest)
	bundleBytes, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation bundle: %v", err)
	}

	log.Println("Fetching trust root")
	trustRootJSON, err := sigstore.FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trust root: %v", err)
	}

	log.Println("Verifying code measurements")
	codeMeasurements, err := sigstore.VerifyAttestation(trustRootJSON, bundleBytes, digest, repo)
	if err != nil {
		return nil, fmt.Errorf("sigstore verify: %v", err)
	}
	auditRecord["code_fingerprint"] = codeMeasurements.Fingerprint()

	log.Printf("Fetching attestation doc from %s", enclaveHost)
	remoteAttestation, err := attestation.Fetch(enclaveHost)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %v", err)
	}

	log.Println("Verifying enclave measurements")
	verification, err := remoteAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying attestation document: %v", err)
	}
	auditRecord["enclave_fingerprint"] = verification.Measurement.Fingerprint()
	auditRecord["attested_public_key"] = verification.PublicKeyFP
	log.Printf("Public key fingerprint: %s", verification.PublicKeyFP)

	// Get remote pubkey fingerprint
	cs, err := tlsConnection(enclaveHost + ":443")
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %v", err)
	}
	pubkeyFP, err := attestation.ConnectionCertFP(*cs)
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %v", err)
	}
	auditRecord["remote_public_key"] = pubkeyFP
	log.Printf("Remote public key fingerprint: %s", pubkeyFP)

	// Compare remote public key fingerprint with attestation public key
	if pubkeyFP != verification.PublicKeyFP {
		auditRecord["status"] = "FAILED"
		auditRecord["error"] = "Remote public key fingerprint does not match attestation public key"
		log.Printf("Remote public key fingerprint does not match attestation public key")
	}

	if repo != "" && codeMeasurements != nil && verification.Measurement != nil {
		if err := codeMeasurements.Equals(verification.Measurement); err != nil {
			auditRecord["status"] = "FAILED"
			auditRecord["error"] = fmt.Sprintf("PCR register mismatch: %v", err)
			log.Printf("PCR register mismatch. Verification failed: %v", err)
			log.Printf("Code: %s", codeMeasurements.Fingerprint())
			log.Printf("Enclave: %s", verification.Measurement.Fingerprint())
		} else {
			log.Println("Measurements match")
		}
	} else {
		log.Printf("Enclave measurement: %s", verification.Measurement.Fingerprint())
	}

	return auditRecord, nil
}
