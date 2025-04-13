package main

import (
	"github.com/spf13/cobra"
)

func init() {
	attestationCmd.AddCommand(attestationVerifyCmd)
}

var attestationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify enclave attestation",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := verifyAttestation()
		return err
	},
}
