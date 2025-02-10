package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilanalytics/verifier/attestation"
	"github.com/tinfoilanalytics/verifier/github"
	"github.com/tinfoilanalytics/verifier/sigstore"
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

		var codeMeasurements, enclaveMeasurements *attestation.Measurement

		if repo != "" {
			log.Printf("Fetching latest release for %s", repo)
			latestTag, eifHash, err := github.FetchLatestRelease(repo)
			if err != nil {
				log.Fatalf("Failed to fetch latest release: %v", err)
			}
			auditRecord["repo"] = repo
			auditRecord["latest_tag"] = latestTag
			auditRecord["eif_hash"] = eifHash

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
			auditRecord["code_fingerprint"] = codeMeasurements.Fingerprint()
		} else {
			log.Warn("No --repo specified, skipping code measurement verification")
			auditRecord["repo"] = "not provided"
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
		auditRecord["enclave_fingerprint"] = enclaveMeasurements.Fingerprint()
		auditRecord["connection_cert_fp"] = fmt.Sprintf("%x", connectionFP)
		auditRecord["attested_cert_fp"] = fmt.Sprintf("%x", attestedCertFP)

		if !bytes.Equal(connectionFP, attestedCertFP) {
			auditRecord["status"] = "FAILED"
			auditRecord["error"] = "Certificate fingerprint mismatch"
			log.Printf("Enclave TLS cert fingerprint: %x", connectionFP)
			log.Printf("Attestation TLS cert fingerprint: %x", attestedCertFP)
			log.Fatalf("Certificate fingerprint mismatch")
		} else {
			log.Printf("Certificate fingerprint match: %x", attestedCertFP)
			auditRecord["status"] = "SUCCESS"
		}

		if repo != "" && codeMeasurements != nil && enclaveMeasurements != nil {
			if err := codeMeasurements.Equals(enclaveMeasurements); err != nil {
				auditRecord["status"] = "FAILED"
				auditRecord["error"] = fmt.Sprintf("PCR register mismatch: %v", err)
				log.Printf("PCR register mismatch. Verification failed: %v", err)
				log.Printf("Code: %s", codeMeasurements.Fingerprint())
				log.Printf("Enclave: %s", enclaveMeasurements.Fingerprint())
			} else {
				log.Println("Verification successful, measurements match")
			}
		} else {
			log.Printf("Enclave measurement: %s", enclaveMeasurements.Fingerprint())
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
