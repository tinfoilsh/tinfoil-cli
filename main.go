package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	enclaveHost, repo string
)

var rootCmd = &cobra.Command{
	Use: "tfverify",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&enclaveHost, "enclave-host", "e", "inference-enclave.tinfoil.sh", "Enclave hostname")
	rootCmd.PersistentFlags().StringVarP(&repo, "repo", "r", "tinfoilanalytics/nitro-enclave-build-demo", "Source repo")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
