package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/tinfoilsh/tinfoil-cli/internal/config"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

var (
	cliTargets       = "production"
	clerkCLIClientID = "DdvUHrDeHCxEqZnN"
	clerkCLIAPIScope = "tinfoil:api"
	clerkIssuer      = "https://clerk.tinfoil.sh"
	fixedAPIOrigin   = defaultControlplaneURL
)

const (
	oauthCallback   = "http://127.0.0.1:49152/oauth/callback"
	keySyncCallback = "http://localhost:49152/callback"
	loginRecordName = "login"
)

var (
	clerkClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	clerkScopePattern    = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,128}$`)
	clerkLoginScopes     = []string{"offline_access", "user:org:read"}
	errNotLoggedIn       = errors.New("not logged in")
)

func fixedKeySyncTargets() (keySyncTargets, error) {
	terminal, ok := map[string]string{"production": "https://terminal.tinfoil.sh", "development": "https://local.tinfoil.sh"}[cliTargets]
	if !ok {
		return keySyncTargets{}, fmt.Errorf("this build has an unknown target profile %q", cliTargets)
	}
	return keySyncTargets{Terminal: terminal, APIOrigin: fixedAPIOrigin,
		Callback: keySyncCallback, Completion: terminal + "/cli/complete"}, nil
}

func clerkScopes() ([]string, error) {
	if !clerkClientIDPattern.MatchString(clerkCLIClientID) || !clerkScopePattern.MatchString(clerkCLIAPIScope) || slices.Contains(clerkLoginScopes, clerkCLIAPIScope) {
		return nil, errors.New("Clerk sign-in is not configured in this build (it needs the registered CLI OAuth client and API scope); use `tinfoil login --api-key` instead")
	}
	return append(slices.Clone(clerkLoginScopes), clerkCLIAPIScope), nil
}

type clerkGrant struct {
	Version      int    `json:"version"`
	Grant        string `json:"grant"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	UserID       string `json:"user_id"`
	Account      string `json:"account"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type syncedDEK struct {
	Version   int    `json:"version"`
	APIOrigin string `json:"api_origin"`
	UserID    string `json:"user_id"`
	DEKID     string `json:"dek_id"`
	DEK       b64u   `json:"dek"`
}

func dekRecordName(apiOrigin, userID string) string {
	return "dek-" + storageHash([]byte(apiOrigin + "\x00" + userID))[:32]
}

func credentialFile(name string) (string, error) {
	config, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(config), "credentials", name+".json"), nil
}

var osCredentials auth.Keyring = auth.OSKeyring{}

func credentialStore() (*auth.Store, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	return auth.NewStore(filepath.Join(filepath.Dir(path), "credentials"), osCredentials), nil
}

func readCredential(name string, out any) (bool, error) {
	store, err := credentialStore()
	if err != nil {
		return false, err
	}
	return store.Read(name, out)
}

func writeCredential(name string, value any) error {
	store, err := credentialStore()
	if err != nil {
		return err
	}
	return store.Write(name, value)
}

func deleteCredential(name string) error {
	store, err := credentialStore()
	if err != nil {
		return err
	}
	return store.Delete(name)
}

func withCredentialLock(fn func() error) error {
	store, err := credentialStore()
	if err != nil {
		return err
	}
	return store.WithLock(fn)
}

func currentGrant() (*clerkGrant, error) {
	var grant clerkGrant
	found, err := readCredential(loginRecordName, &grant)
	if err != nil || !found {
		return nil, err
	}
	if grant.Version != 1 || !validID16(grant.Grant) || grant.Issuer != clerkIssuer || grant.ClientID != clerkCLIClientID ||
		!keybundle.ValidUserID(grant.UserID) || !keybundle.ValidAccount(grant.Account) || grant.AccessToken == "" {
		return nil, errors.New("the saved login belongs to another CLI build or is damaged; run `tinfoil login`")
	}
	return &grant, nil
}

func syncedKey(login *clerkGrant, userID string) (*syncedDEK, error) {
	if login == nil || login.UserID != userID {
		return nil, nil
	}
	var dek syncedDEK
	found, err := readCredential(dekRecordName(fixedAPIOrigin, userID), &dek)
	if err != nil || !found {
		return nil, err
	}
	if dek.Version != 1 || dek.APIOrigin != fixedAPIOrigin || dek.UserID != userID || !validID16(dek.DEKID) || len(dek.DEK) != 32 {
		return nil, errors.New("the synced key on this machine is damaged; run `tinfoil login --sync`")
	}
	return &dek, nil
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
