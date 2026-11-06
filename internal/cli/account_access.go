package cli

import (
	"net/http"
	"os"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
)

type credentialStoreFactory func() (*auth.Store, error)
type authenticatedClientFactory func(commandIO) (*cpClient, error)
type scopeClientFactory func(commandIO) (accountScope, *cpClient, error)

type accountAccess struct {
	apiOrigin string
	auth      func(commandIO) (*auth.Service, error)
	client    func(commandIO, cliConfig) *cpClient
}

func newAccountAccess(settings auth.BuildSettings, currentVersion string, credentials credentialStoreFactory, transport *http.Client) *accountAccess {
	accounts := &accountAccess{apiOrigin: settings.APIOrigin}
	accounts.auth = func(streams commandIO) (*auth.Service, error) {
		store, err := credentials()
		if err != nil {
			return nil, err
		}
		return auth.New(settings, store, transport, currentVersion, auth.Lifecycle{
			CleanupResources: removeExportedKeys,
			LoginCommitted: func() error {
				cfg, path, err := loadConfig(streams)
				if err == nil && cfg.APIKey != "" && envAdminAPIKey() == "" {
					if _, statErr := os.Stat(path); statErr == nil {
						_, _, err = deleteConfig()
					}
				}
				return err
			},
		}), nil
	}
	accounts.client = func(streams commandIO, cfg cliConfig) *cpClient {
		return newCPClient(cfg, currentVersion, settings.APIOrigin, transport, func() (*auth.Service, error) {
			return accounts.auth(streams)
		})
	}
	return accounts
}
