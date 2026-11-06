package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/tinfoilsh/tinfoil-cli/internal/config"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
)

var errNotLoggedIn = errors.New("not logged in")

type clerkGrant = auth.Grant
type syncedDEK = auth.SyncedDEK

func credentialStore(keyring auth.Keyring) (*auth.Store, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	return auth.NewStore(filepath.Join(filepath.Dir(path), "credentials"), keyring), nil
}

func (a *accountAccess) currentGrant(streams commandIO) (*clerkGrant, error) {
	service, err := a.auth(streams)
	if err != nil {
		return nil, err
	}
	return service.CurrentGrant()
}

func (a *accountAccess) syncedKey(streams commandIO, login *clerkGrant, userID string) (*syncedDEK, error) {
	service, err := a.auth(streams)
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

func loadConfig(streams commandIO) (cliConfig, string, error) {
	result, err := config.Load()
	if err != nil {
		return cliConfig{}, "", err
	}
	if result.Diagnostic != nil {
		fmt.Fprintf(streams.err, "warning: %v\n", result.Diagnostic)
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
func (a *accountAccess) requireAuth(streams commandIO) (cliConfig, error) {
	cfg, _, err := loadConfig(streams)
	if err != nil {
		return cliConfig{}, err
	}
	if cfg.APIKey == "" {
		if cfg.login, err = a.currentGrant(streams); err != nil {
			return cliConfig{}, err
		}
		if cfg.login == nil {
			return cliConfig{}, fmt.Errorf("%w: run `tinfoil login` or set %s", errNotLoggedIn, envAdminKey)
		}
		cfg.ControlplaneURL = a.apiOrigin
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
