package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const defaultVersion = "dev"

var (
	enclaveHost, repo string
	verbose, trace    bool
	version           = defaultVersion
)

func newRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tinfoil",
		Version: version,
	}
}

var rootCmd = newRootCommand()

func init() {
	rootCmd.PersistentFlags().StringVarP(&enclaveHost, "host", "e", "", "Enclave hostname")
	rootCmd.PersistentFlags().StringVarP(&repo, "repo", "r", "", "Enclave config repo")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "t", false, "Trace output")
}

func main() {
	if trace {
		log.SetLevel(log.TraceLevel)
	} else if verbose {
		log.SetLevel(log.InfoLevel)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
