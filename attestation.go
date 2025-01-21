package main

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
}

var attestationCmd = &cobra.Command{
	Use:   "attestation",
	Short: "Attestation commands",
}
