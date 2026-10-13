package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const defaultVersion = "dev"

var (
	enclaveHost, repo string
	localConfigFile   string
	verbose, trace    bool
	version           = defaultVersion
	// exitCode is the status a command wants the process to end with, for the
	// ones that stand in for another program.
	exitCode int
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tinfoil",
		Version: version,
	}
	cmd.PersistentFlags().StringVar(&localConfigFile, "config", "", "Local config file to launch or trust for verification")
	return cmd
}

var rootCmd = newRootCommand()

func init() {
	rootCmd.PersistentFlags().StringVarP(&enclaveHost, "enclave", "e", "", "Enclave hostname (for example inference.tinfoil.sh)")
	rootCmd.PersistentFlags().StringVarP(&repo, "repo", "r", "", "Expected config source: owner/name[@tag][@sha256:digest]")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "t", false, "Trace output")
}

func main() {
	if trace {
		log.SetLevel(log.TraceLevel)
	} else if verbose {
		log.SetLevel(log.InfoLevel)
	}

	waitForUpdateCheck := func() (string, bool) { return "", false }
	if !isSelfUpdateCommand(rootCmd, os.Args[1:]) {
		waitForUpdateCheck = startUpdateCheck()
	}

	err := rootCmd.Execute()

	if latest, ok := waitForUpdateCheck(); ok {
		printUpdateNotice(latest)
	}

	if err != nil {
		exitCode = 1
	}
	os.Exit(exitCode)
}
