package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultControlplaneURL = "https://api.tinfoil.sh"

	defaultNBucketHost = "named-bucket.tinfoil.sh"
	defaultNBucketRepo = "tinfoilsh/named-bucket"

	envAPIKey      = "TINFOIL_API_KEY"
	envCPURL       = "TINFOIL_CONTROLPLANE_URL"
	envConfigPath  = "TINFOIL_CONFIG"

	envNBucketHost   = "TINFOIL_NBUCKET_HOST"
	envNBucketRepo   = "TINFOIL_NBUCKET_REPO"
	envNBucketAPIKey = "TINFOIL_NBUCKET_API_KEY"
	envNBucketMaster = "TINFOIL_NBUCKET_MASTER"
)

type cliConfig struct {
	ControlplaneURL string         `json:"controlplane_url"`
	APIKey          string         `json:"api_key"`
	NBucket         *nbucketConfig `json:"nbucket,omitempty"`
}

type nbucketConfig struct {
	Host   string `json:"host"`
	Repo   string `json:"repo"`
	APIKey string `json:"api_key"`
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
	if v := strings.TrimSpace(os.Getenv(envAPIKey)); v != "" {
		cfg.APIKey = v
	}

	if cfg.ControlplaneURL == "" {
		cfg.ControlplaneURL = defaultControlplaneURL
	}
	cfg.ControlplaneURL = strings.TrimRight(cfg.ControlplaneURL, "/")

	return cfg, path, nil
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
		return cliConfig{}, fmt.Errorf("not logged in: run `tinfoil login` or set %s", envAPIKey)
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
