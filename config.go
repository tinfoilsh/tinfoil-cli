package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// Trusted production defaults, overridable only at build time with -ldflags -X.
// Nothing at runtime selects another destination for a Clerk login.
var (
	cliTargets       = "production"
	clerkCLIClientID = "DdvUHrDeHCxEqZnN"
	clerkCLIAPIScope = "tinfoil:api"
	clerkIssuer      = "https://clerk.tinfoil.sh"
	fixedAPIOrigin   = defaultControlplaneURL
)

const (
	oauthCallback       = "http://127.0.0.1:49152/oauth/callback"
	keySyncCallback     = "http://localhost:49152/callback"
	credentialService   = "tinfoil-cli"
	loginRecordName     = "login"
	credentialLockWait  = 45 * time.Second
	credentialLockRetry = 20 * time.Millisecond
)

var (
	clerkClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	clerkScopePattern    = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,128}$`)
	clerkLoginScopes     = []string{"offline_access", "user:org:read"}
	errNotLoggedIn       = errors.New("not logged in")
)

// fixedKeySyncTargets are bound locally into a key transfer after Clerk login.
func fixedKeySyncTargets() (keySyncTargets, error) {
	terminal, ok := map[string]string{"production": "https://terminal.tinfoil.sh", "development": "https://local.tinfoil.sh"}[cliTargets]
	if !ok {
		return keySyncTargets{}, fmt.Errorf("this build has an unknown target profile %q", cliTargets)
	}
	return keySyncTargets{Terminal: terminal, APIOrigin: fixedAPIOrigin,
		Callback: keySyncCallback, Completion: terminal + "/cli/complete"}, nil
}

// clerkScopes is the scope set every CLI grant must carry; an unconfigured build cannot sign in.
func clerkScopes() ([]string, error) {
	if !clerkClientIDPattern.MatchString(clerkCLIClientID) || !clerkScopePattern.MatchString(clerkCLIAPIScope) || slices.Contains(clerkLoginScopes, clerkCLIAPIScope) {
		return nil, errors.New("Clerk sign-in is not configured in this build (it needs the registered CLI OAuth client and API scope); use `tinfoil login --api-key` instead")
	}
	return append(slices.Clone(clerkLoginScopes), clerkCLIAPIScope), nil
}

// clerkGrant is one Clerk login, scoped to its issuer, client, user and granted account.
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

// syncedDEK is the key-bundle DEK synced to this machine for one API origin and user.
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

// credentialSlot is the file that selects where one credential record lives, so the
// newest write wins and a deletion cannot be undone when an OS credential service
// recovers. Keyring means the service holds the record, or may still hold an older
// copy that a deletion must remove; Record is the record itself, in a 0600 file under
// a 0700 directory, when the service failed; Deleted marks a removed record whose
// service copy still awaits deletion.
// osCredentials is the OS credential service; tests substitute outages.
var osCredentials interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
} = osKeyring{}

type osKeyring struct{}

func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeyring) Set(service, user, secret string) error   { return keyring.Set(service, user, secret) }
func (osKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

type credentialSlot struct {
	Keyring bool            `json:"keyring"`
	Record  json.RawMessage `json:"record,omitempty"`
	Deleted bool            `json:"deleted,omitempty"`
}

func readCredentialSlot(name string) (string, *credentialSlot, error) {
	path, err := credentialFile(name)
	if err != nil {
		return "", nil, err
	}
	var slot credentialSlot
	if err := readStorageJSON(path, &slot); errors.Is(err, os.ErrNotExist) {
		return path, nil, nil
	} else if err != nil {
		return path, nil, fmt.Errorf("%s: %w", path, err)
	}
	return path, &slot, nil
}

// readCredential never substitutes another copy for the selected one: an unavailable
// service is an error, not an empty or older record.
func readCredential(name string, out any) (bool, error) {
	_, slot, err := readCredentialSlot(name)
	if err != nil || slot == nil || slot.Deleted {
		return false, err
	}
	if slot.Record != nil {
		return true, json.Unmarshal(slot.Record, out)
	}
	secret, err := osCredentials.Get(credentialService, name)
	if err != nil {
		return false, fmt.Errorf("reading %s from the OS credential service: %w", name, err)
	}
	return true, json.Unmarshal([]byte(secret), out)
}

func writeCredential(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	path, previous, err := readCredentialSlot(name)
	if err != nil {
		return err
	}
	if err := prepareStorageDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	// Make a service copy discoverable before creating it, keeping the current selection.
	if previous == nil || !previous.Keyring {
		marker := credentialSlot{Keyring: true, Deleted: previous == nil}
		if previous != nil {
			marker.Record = previous.Record
		}
		if err := writeCredentialSlot(path, marker); err != nil {
			return err
		}
	}
	slot := credentialSlot{Keyring: true}
	if osCredentials.Set(credentialService, name, string(data)) != nil {
		slot.Record = data
	}
	return writeCredentialSlot(path, slot)
}

func writeCredentialSlot(path string, slot credentialSlot) error {
	encoded, err := json.Marshal(slot)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return writeStorageFile(path, encoded, false)
}

// deleteCredential leaves a tombstone selected, and fails, while the service still holds a copy.
func deleteCredential(name string) error {
	path, slot, err := readCredentialSlot(name)
	if slot == nil && err == nil {
		return nil
	}
	if err != nil || slot.Keyring {
		if err := osCredentials.Delete(credentialService, name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return errors.Join(fmt.Errorf("%s is no longer used, but the OS credential service still holds a copy; rerun `tinfoil logout` when it is available: %w", name, err),
				writeCredentialSlot(path, credentialSlot{Keyring: true, Deleted: true}))
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// withCredentialLock serializes login commits, token rotation, key exports and logout.
func withCredentialLock(fn func() error) error {
	path, err := credentialFile("credentials")
	if err != nil {
		return err
	}
	unlock, err := acquireStorageLock(path)
	for deadline := time.Now().Add(credentialLockWait); err != nil && time.Now().Before(deadline); {
		time.Sleep(credentialLockRetry)
		unlock, err = acquireStorageLock(path)
	}
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// currentGrant returns this build's Clerk login, or nil when there is none.
func currentGrant() (*clerkGrant, error) {
	var grant clerkGrant
	found, err := readCredential(loginRecordName, &grant)
	if err != nil || !found {
		return nil, err
	}
	if grant.Version != 1 || !validID16(grant.Grant) || grant.Issuer != clerkIssuer || grant.ClientID != clerkCLIClientID ||
		!userIDPattern.MatchString(grant.UserID) || !accountPattern.MatchString(grant.Account) || grant.AccessToken == "" {
		return nil, errors.New("the saved login belongs to another CLI build or is damaged; run `tinfoil login`")
	}
	return &grant, nil
}

// syncedKey returns the DEK this login synced for user, or nil when keys were not synced.
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
	defaultControlplaneURL = "https://api.tinfoil.sh"

	envAdminKey     = "TINFOIL_ADMIN_KEY"
	envAPIKey       = "TINFOIL_API_KEY"
	envTunnelAPIKey = "TINFOIL_TUNNEL_API_KEY"

	adminKeyPrefix = "admin_"
	envCPURL       = "TINFOIL_CONTROLPLANE_URL"
	envConfigPath  = "TINFOIL_CONFIG"
)

type cliConfig struct {
	ControlplaneURL string `json:"controlplane_url"`
	APIKey          string `json:"api_key"`
	// login authenticates when no admin key is configured; it always targets fixedAPIOrigin.
	login *clerkGrant
}

func configPath() (string, error) {
	if p := os.Getenv(envConfigPath); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".tinfoil", "config.json"), nil
}

func loadConfig() (cliConfig, string, error) {
	path, err := configPath()
	if err != nil {
		return cliConfig{}, "", err
	}

	cfg := cliConfig{ControlplaneURL: defaultControlplaneURL}

	// Reading the saved file is best-effort. A corrupt file (mid-write
	// truncation, hand-editing typo) must not lock the user out — the env
	// vars TINFOIL_API_KEY / TINFOIL_CONTROLPLANE_URL are documented as
	// overrides, and `tinfoil login` itself goes through this path so a
	// hard error here would also prevent rewriting the bad file.
	if data, ferr := os.ReadFile(path); ferr == nil {
		if jerr := json.Unmarshal(data, &cfg); jerr != nil {
			fmt.Fprintf(os.Stderr, "warning: ignoring malformed %s (%v); falling back to defaults and env overrides\n", path, jerr)
			cfg = cliConfig{ControlplaneURL: defaultControlplaneURL}
		}
	} else if !errors.Is(ferr, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: cannot read %s (%v); falling back to defaults and env overrides\n", path, ferr)
	}

	if v := strings.TrimSpace(os.Getenv(envCPURL)); v != "" {
		cfg.ControlplaneURL = v
	}
	if v := envAdminAPIKey(); v != "" {
		cfg.APIKey = v
	}

	if cfg.ControlplaneURL == "" {
		cfg.ControlplaneURL = defaultControlplaneURL
	}
	cfg.ControlplaneURL = strings.TrimRight(cfg.ControlplaneURL, "/")

	return cfg, path, nil
}

// envAdminAPIKey returns the admin key override from the environment.
// TINFOIL_ADMIN_KEY takes precedence. TINFOIL_API_KEY is shared with the
// inference SDKs and commonly holds a tk_ key, so it only counts when it
// actually carries an admin key; otherwise the saved login stays in effect.
func envAdminAPIKey() string {
	if v := strings.TrimSpace(os.Getenv(envAdminKey)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(envAPIKey)); strings.HasPrefix(v, adminKeyPrefix) {
		return v
	}
	return ""
}

func saveConfig(cfg cliConfig) (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return path, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return path, fmt.Errorf("encoding config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return path, fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return path, fmt.Errorf("renaming to %s: %w", path, err)
	}
	return path, nil
}

func deleteConfig() (string, bool, error) {
	path, err := configPath()
	if err != nil {
		return "", false, err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, false, nil
		}
		return path, false, fmt.Errorf("removing %s: %w", path, err)
	}
	return path, true, nil
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

// validateControlplaneURL rejects URLs that would send the admin bearer
// token over plaintext HTTP. Loopback hosts are allowed for local dev so
// you can point the CLI at a controlplane running on localhost.
func validateControlplaneURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("controlplane URL is empty (set %s or run `tinfoil login --url ...`)", envCPURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid controlplane URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid controlplane URL %q: missing host (expected https://...)", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("controlplane URL %q must use https — refusing to send admin API key over plaintext (http is allowed only for localhost)", raw)
	default:
		return fmt.Errorf("controlplane URL %q must use https://", raw)
	}
}
