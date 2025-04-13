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
	Use: "tinfoil",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&enclaveHost, "host", "e", "", "Enclave hostname")
	rootCmd.PersistentFlags().StringVarP(&repo, "repo", "r", "", "Source repo")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
