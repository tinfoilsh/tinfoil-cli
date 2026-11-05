package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/tinfoilsh/tinfoil-cli/internal/config"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
)

var (
	cliTargets       = "production"
	clerkCLIClientID = "DdvUHrDeHCxEqZnN"
	clerkCLIAPIScope = "tinfoil:api"
	clerkIssuer      = "https://clerk.tinfoil.sh"
	fixedAPIOrigin   = defaultControlplaneURL
)

var errNotLoggedIn = errors.New("not logged in")

type clerkGrant = auth.Grant
type syncedDEK = auth.SyncedDEK

var osCredentials auth.Keyring = auth.OSKeyring{}

func credentialStore() (*auth.Store, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	return auth.NewStore(filepath.Join(filepath.Dir(path), "credentials"), osCredentials), nil
}

func currentGrant() (*clerkGrant, error) {
	service, err := authService()
	if err != nil {
		return nil, err
	}
	return service.CurrentGrant()
}

func syncedKey(login *clerkGrant, userID string) (*syncedDEK, error) {
	service, err := authService()
	if err != nil {
		return nil, err
	}
	return service.SyncedKey(login, userID)
}

const (
	defaultControlplaneURL = config.DefaultControlplaneURL

	envAdminKey     = config.EnvAdminKey
	envAPIKey       = config.EnvAPIKey
	envTunnelAPIKey = "TINFOIL_TUNNEL_API_KEY"

	adminKeyPrefix = config.AdminKeyPrefix
	envCPURL       = config.EnvControlplaneURL
	envConfigPath  = config.EnvConfigPath
)

type cliConfig struct {
	ControlplaneURL string `json:"controlplane_url"`
	APIKey          string `json:"api_key"`
	login           *clerkGrant
}

func configPath() (string, error) {
	return config.Path()
}

func loadConfig() (cliConfig, string, error) {
	result, err := config.Load()
	if err != nil {
		return cliConfig{}, "", err
	}
	if result.Diagnostic != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", result.Diagnostic)
	}
	return cliConfig{ControlplaneURL: result.Config.ControlplaneURL, APIKey: result.Config.APIKey}, result.Path, nil
}

func envAdminAPIKey() string {
	return config.EnvAdminAPIKey()
}

func saveConfig(cfg cliConfig) (string, error) {
	return config.Save(config.Config{ControlplaneURL: cfg.ControlplaneURL, APIKey: cfg.APIKey})
}

func deleteConfig() (string, bool, error) {
	return config.Delete()
}

// requireAuth returns the loaded config or an error explaining how to
// authenticate. Use it from commands that need to talk to the controlplane.
func requireAuth() (cliConfig, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return cliConfig{}, err
	}
	if cfg.APIKey == "" {
		if cfg.login, err = currentGrant(); err != nil {
			return cliConfig{}, err
		}
		if cfg.login == nil {
			return cliConfig{}, fmt.Errorf("%w: run `tinfoil login` or set %s", errNotLoggedIn, envAdminKey)
		}
		cfg.ControlplaneURL = fixedAPIOrigin
		return cfg, nil
	}
	if err := validateControlplaneURL(cfg.ControlplaneURL); err != nil {
		return cliConfig{}, err
	}
	return cfg, nil
}

func validateControlplaneURL(raw string) error {
	return controlplane.ValidateURL(raw)
}
