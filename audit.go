package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

var auditLogFile string

func init() {
	attestationCmd.AddCommand(attestationAuditCmd)
	attestationAuditCmd.Flags().StringVarP(&auditLogFile, "log-file", "l", "", "Path to write the audit log (default stdout)")
}

var attestationAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify enclave attestation and record an audit log entry",
	Run: func(cmd *cobra.Command, args []string) {
		auditRecord := make(map[string]interface{})
		auditRecord["timestamp"] = time.Now().UTC().Format(time.RFC3339)
		auditRecord["enclave_host"] = enclaveHost

		log.Printf("Fetching latest release for %s", repo)
		digest, err := github.FetchLatestDigest(repo)
		if err != nil {
			log.Fatalf("Failed to fetch latest release: %v", err)
		}
		auditRecord["repo"] = repo
		auditRecord["digest"] = digest

		log.Printf("Fetching sigstore bundle from %s for digest %s", repo, digest)
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
		auditRecord["code_fingerprint"] = codeMeasurements.Fingerprint()

		log.Printf("Fetching attestation doc from %s", enclaveHost)
		remoteAttestation, err := attestation.Fetch(enclaveHost)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Verifying enclave measurements")
		verification, err := remoteAttestation.Verify()
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}
		auditRecord["enclave_fingerprint"] = verification.Measurement.Fingerprint()
		auditRecord["attested_cert_fp"] = fmt.Sprintf("%x", verification.CertFP)
		log.Printf("Certificate fingerprint: %x", verification.CertFP)

		if repo != "" && codeMeasurements != nil && verification.Measurement != nil {
			if err := codeMeasurements.Equals(verification.Measurement); err != nil {
				auditRecord["status"] = "FAILED"
				auditRecord["error"] = fmt.Sprintf("PCR register mismatch: %v", err)
				log.Printf("PCR register mismatch. Verification failed: %v", err)
				log.Printf("Code: %s", codeMeasurements.Fingerprint())
				log.Printf("Enclave: %s", verification.Measurement.Fingerprint())
			} else {
				log.Println("Verification successful, measurements match")
			}
		} else {
			log.Printf("Enclave measurement: %s", verification.Measurement.Fingerprint())
		}

		// Output the audit record as pretty JSON.
		auditJSON, err := json.MarshalIndent(auditRecord, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling audit record: %v", err)
		}

		if auditLogFile != "" {
			f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("Failed to open audit log file: %v", err)
			}
			defer f.Close()
			if _, err := f.Write(append(auditJSON, '\n')); err != nil {
				log.Fatalf("Failed to write audit log: %v", err)
			}
			log.Printf("Audit record written to %s", auditLogFile)
		} else {
			fmt.Println(string(auditJSON))
		}
	},
}
