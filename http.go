package main

import (
	"github.com/spf13/cobra"

	"github.com/tinfoilanalytics/verifier/pkg/client"
)

func secureClient() *client.SecureClient {
	return client.NewSecureClient(enclaveHost, repo)
}

func init() {
	rootCmd.AddCommand(httpCmd)
}

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Make verified HTTP requests",
}
