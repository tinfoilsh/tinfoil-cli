package main

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var auditLogFile string

func init() {
	attestationCmd.AddCommand(attestationAuditCmd)
	attestationAuditCmd.Flags().StringVarP(&auditLogFile, "log-file", "l", "", "Path to write the audit log (default stdout)")
}

var attestationAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify enclave attestation and record an audit log entry",
	RunE: func(cmd *cobra.Command, args []string) error {
		auditRecord, err := verifyAttestation()
		if err != nil {
			return err
		}

		auditJSON, err := json.MarshalIndent(auditRecord, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding audit record: %v", err)
		}

		if auditLogFile != "" {
			if err := os.WriteFile(auditLogFile, append(auditJSON, '\n'), 0644); err != nil {
				return fmt.Errorf("failed to write audit log: %v", err)
			}
			log.Printf("Audit record written to %s", auditLogFile)
		} else {
			fmt.Println(string(auditJSON))
		}

		return nil
	},
}
