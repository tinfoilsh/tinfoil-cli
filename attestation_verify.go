package main

import (
	"bytes"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilanalytics/verifier/attestation"
	"github.com/tinfoilanalytics/verifier/github"
	"github.com/tinfoilanalytics/verifier/sigstore"
)

func init() {
	attestationCmd.AddCommand(attestationVerifyCmd)
}

var attestationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify enclave attestation",
	Run: func(cmd *cobra.Command, args []string) {
		var codeMeasurements, enclaveMeasurements *attestation.Measurement

		if repo != "" {
			log.Printf("Fetching latest release for %s", repo)
			latestTag, eifHash, err := github.FetchLatestRelease(repo)
			if err != nil {
				log.Fatalf("Failed to fetch latest release: %v", err)
			}

			log.Printf("Fetching sigstore bundle from %s for latest version %s EIF %s", latestTag, repo, eifHash)
			bundleBytes, err := github.FetchAttestationBundle(repo, eifHash)
			if err != nil {
				log.Fatal(err)
			}

			log.Println("Fetching trust root")
			trustRootJSON, err := sigstore.FetchTrustRoot()
			if err != nil {
				log.Fatal(err)
			}

			log.Println("Verifying code measurements")
			codeMeasurements, err = sigstore.VerifyAttestation(trustRootJSON, bundleBytes, eifHash, repo)
			if err != nil {
				log.Fatalf("Failed to verify source measurements: %v", err)
			}
		} else {
			log.Warn("No --repo specified, skipping code measurement verification")
		}

		log.Printf("Fetching attestation doc from %s", enclaveHost)
		remoteAttestation, connectionFP, err := attestation.Fetch(enclaveHost)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Verifying enclave measurements")
		var attestedCertFP []byte
		enclaveMeasurements, attestedCertFP, err = remoteAttestation.Verify()
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}

		if !bytes.Equal(connectionFP, attestedCertFP) {
			log.Printf("Enclave TLS cert fingerprint: %x", connectionFP)
			log.Printf("Attestation TLS cert fingerprint: %x", attestedCertFP)
			log.Fatalf("Certificate fingerprint mismatch")
		} else {
			log.Printf("Certificate fingerprint match: %x", attestedCertFP)
		}

		if repo != "" {
			if codeMeasurements != nil && enclaveMeasurements != nil {
				if err := codeMeasurements.Equals(enclaveMeasurements); err != nil {
					log.Printf("PCR register mismatch. Verification failed: %v", err)
					log.Printf("Code: %s", codeMeasurements.Fingerprint())
					log.Printf("Enclave: %s", enclaveMeasurements.Fingerprint())
				} else {
					log.Println("Verification successful, measurements match")
				}
			}
		} else {
			log.Printf("Enclave measurement: %s", enclaveMeasurements.Fingerprint())
		}
	},
}
