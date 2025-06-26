package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	attestationCmd.AddCommand(attestationVerifyCmd)
	attestationVerifyCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
}

var (
	jsonOutput bool
)

var attestationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify enclave attestation",
	RunE: func(cmd *cobra.Command, args []string) error {
		record, err := verifyAttestation()
		if err != nil {
			return err
		}

		if jsonOutput {
			output, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				return fmt.Errorf("error marshaling JSON: %v", err)
			}
			fmt.Println(string(output))
			return nil
		}

		return nil
	},
}
