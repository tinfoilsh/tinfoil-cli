package cli

import (
	"fmt"
	"os"

	"github.com/tinfoilsh/tinfoil-cli/internal/trust"
)

const (
	envKnownConfigs = "TINFOIL_KNOWN_CONFIGS"
	envTrust        = "TINFOIL_TRUST"

	policyModePrompt    = trust.ModePrompt
	policyModeFrozen    = trust.ModeFrozen
	policyRecordOrg     = trust.RecordOrg
	policyRecordProject = trust.RecordProject
	policyRecordPin     = trust.RecordPin
)

type connectionPolicy = trust.Policy

func trustLocation() (trust.Location, error) {
	location := trust.Location{Trust: os.Getenv(envTrust), KnownConfigs: os.Getenv(envKnownConfigs)}
	if location.Trust == "" && location.KnownConfigs == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return location, fmt.Errorf("locating home directory: %w", err)
		}
		location.Home = home
	}
	return location, nil
}

func loadConnectionPolicy() (connectionPolicy, error) {
	location, err := trustLocation()
	if err != nil {
		return connectionPolicy{Mode: policyModePrompt, Record: policyRecordProject}, err
	}
	return location.Load()
}

func loadConnectionPolicyFrom(path string) (connectionPolicy, error) {
	return trust.Load(path)
}
