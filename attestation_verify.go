package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

func init() {
	attestationCmd.AddCommand(attestationVerifyCmd)
}

var attestationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify enclave attestation",
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Fetching latest release for %s", repo)
		digest, err := github.FetchLatestDigest(repo)
		if err != nil {
			log.Fatalf("Failed to fetch latest release: %v", err)
		}

		log.Printf("Fetching sigstore bundle from %s for latest release with digest %s", repo, digest)
		bundleBytes, err := github.FetchAttestationBundle(repo, digest)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Fetching trust root")
		trustRootJSON, err := sigstore.FetchTrustRoot()
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Verifying code measurements")
		codeMeasurements, err := sigstore.VerifyAttestation(trustRootJSON, bundleBytes, digest, repo)
		if err != nil {
			log.Fatalf("Failed to verify source measurements: %v", err)
		}

		log.Printf("Fetching attestation doc from %s", enclaveHost)
		attestation, err := attestation.Fetch(enclaveHost)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Verifying enclave measurements")
		verification, err := attestation.Verify()
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}

		log.Printf("Certificate fingerprint: %x", verification.CertFP)

		enclaveMeasurements := verification.Measurement
		if codeMeasurements != nil && enclaveMeasurements != nil {
			if err := codeMeasurements.Equals(enclaveMeasurements); err != nil {
				log.Printf("PCR register mismatch. Verification failed: %v", err)
				log.Printf("Code: %s", codeMeasurements.Fingerprint())
				log.Printf("Enclave: %s", enclaveMeasurements.Fingerprint())
			} else {
				log.Println("Verification successful, measurements match")
			}
		}
	},
}
