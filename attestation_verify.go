package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newAttestationVerifyCommand(attestationVerifyOpts *attestationVerifyOptions, rootOpts *rootOptions) *cobra.Command {
	attestationVerifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify enclave attestation",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := log.New()
			if attestationVerifyOpts.jsonFile != "" || attestationVerifyOpts.jsonOutput {
				logger.SetOutput(io.Discard)
			}

			// Override and enable logging if verbose or trace is set
			if rootOpts.verbose {
				logger.SetLevel(log.DebugLevel)
			} else if rootOpts.trace {
				logger.SetLevel(log.TraceLevel)
			}

			record, err := verifyAttestation(rootOpts, logger)
			if err != nil {
				return err
			}

			output, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				return fmt.Errorf("error marshaling JSON: %v", err)
			}

			if attestationVerifyOpts.jsonOutput {
				fmt.Fprintln(commandStreams(cmd).out, string(output))
			}

			if attestationVerifyOpts.jsonFile != "" {
				if err := os.WriteFile(attestationVerifyOpts.jsonFile, output, 0644); err != nil {
					return fmt.Errorf("error writing JSON to file: %v", err)
				}
			}

			return record.verificationError()
		},
	}
	attestationVerifyCmd.Flags().BoolVarP(&attestationVerifyOpts.jsonOutput, "json", "j", false, "Output in JSON format")
	attestationVerifyCmd.Flags().StringVarP(&attestationVerifyOpts.jsonFile, "log-file", "l", "", "Path to write the JSON log")
	return attestationVerifyCmd
}
