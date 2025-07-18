package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	attestationCmd.AddCommand(attestationVerifyCmd)
	attestationVerifyCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	attestationVerifyCmd.Flags().StringVarP(&jsonFile, "log-file", "l", "", "Path to write the JSON log")
}

var (
	jsonOutput bool
	jsonFile   string
)

var attestationVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify enclave attestation",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New()
		if jsonFile != "" || jsonOutput {
			logger.SetOutput(io.Discard)
		}

		// Override and enable logging if verbose or trace is set
		if verbose {
			logger.SetLevel(log.DebugLevel)
		} else if trace {
			logger.SetLevel(log.TraceLevel)
		}

		record, err := verifyAttestation(logger)
		if err != nil {
			return err
		}

		output, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %v", err)
		}

		if jsonOutput {
			fmt.Println(string(output))
			return nil
		}

		if jsonFile != "" {
			if err := os.WriteFile(jsonFile, output, 0644); err != nil {
				return fmt.Errorf("error writing JSON to file: %v", err)
			}
		}

		return nil
	},
}
