// Package cli assembles commands and adapts their inputs and output to application services.
package cli

import (
	"io"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
)

const (
	DefaultVersion   = defaultVersion
	DefaultTargets   = "production"
	DefaultClientID  = "DdvUHrDeHCxEqZnN"
	DefaultAPIScope  = "tinfoil:api"
	DefaultIssuer    = "https://clerk.tinfoil.sh"
	DefaultAPIOrigin = defaultControlplaneURL
)

type Build struct {
	Version   string
	Targets   string
	ClientID  string
	APIScope  string
	Issuer    string
	APIOrigin string
}

func defaultAuthSettings() auth.BuildSettings {
	return auth.BuildSettings{Targets: DefaultTargets, ClientID: DefaultClientID, APIScope: DefaultAPIScope, Issuer: DefaultIssuer, APIOrigin: DefaultAPIOrigin}
}

func Run(args []string, build Build, input io.Reader, output, diagnostic io.Writer) int {
	settings := auth.BuildSettings{Targets: build.Targets, ClientID: build.ClientID, APIScope: build.APIScope, Issuer: build.Issuer, APIOrigin: build.APIOrigin}
	return run(args, commandDependencies{version: build.Version, authSettings: &settings, in: input, out: output, err: diagnostic})
}
