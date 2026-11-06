package main

import (
	"os"

	"github.com/tinfoilsh/tinfoil-cli/internal/cli"
)

var (
	version          = cli.DefaultVersion
	cliTargets       = cli.DefaultTargets
	clerkCLIClientID = cli.DefaultClientID
	clerkCLIAPIScope = cli.DefaultAPIScope
	clerkIssuer      = cli.DefaultIssuer
	fixedAPIOrigin   = cli.DefaultAPIOrigin
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.Build{
		Version:   version,
		Targets:   cliTargets,
		ClientID:  clerkCLIClientID,
		APIScope:  clerkCLIAPIScope,
		Issuer:    clerkIssuer,
		APIOrigin: fixedAPIOrigin,
	}, os.Stdin, os.Stdout, os.Stderr))
}
