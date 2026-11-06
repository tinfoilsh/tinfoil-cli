package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const (
	DefaultControlplaneURL = "https://api.tinfoil.sh"
	EnvAdminKey            = "TINFOIL_ADMIN_KEY"
	EnvAPIKey              = "TINFOIL_API_KEY"
	AdminKeyPrefix         = "admin_"
	EnvControlplaneURL     = "TINFOIL_CONTROLPLANE_URL"
	EnvConfigPath          = "TINFOIL_CONFIG"
)

type Config struct {
	ControlplaneURL string `json:"controlplane_url"`
	APIKey          string `json:"api_key"`
}

type Result struct {
	Config     Config
	Path       string
	Diagnostic error
}

func Path() (string, error) {
	if p := os.Getenv(EnvConfigPath); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".tinfoil", "config.json"), nil
}

func Load() (Result, error) {
	path, err := Path()
	if err != nil {
		return Result{}, err
	}

	cfg := Config{ControlplaneURL: DefaultControlplaneURL}
	var diagnostic error

	// Reading the saved file is best-effort. A corrupt file (mid-write
	// truncation, hand-editing typo) must not lock the user out — the env
	// vars TINFOIL_API_KEY / TINFOIL_CONTROLPLANE_URL are documented as
	// overrides, and `tinfoil login` itself goes through this path so a
	// hard error here would also prevent rewriting the bad file.
	if data, ferr := os.ReadFile(path); ferr == nil {
		if jerr := json.Unmarshal(data, &cfg); jerr != nil {
			diagnostic = fmt.Errorf("ignoring malformed %s (%v); falling back to defaults and env overrides", path, jerr)
			cfg = Config{ControlplaneURL: DefaultControlplaneURL}
		}
	} else if !errors.Is(ferr, os.ErrNotExist) {
		diagnostic = fmt.Errorf("cannot read %s (%v); falling back to defaults and env overrides", path, ferr)
	}

	if v := strings.TrimSpace(os.Getenv(EnvControlplaneURL)); v != "" {
		cfg.ControlplaneURL = v
	}
	if v := EnvAdminAPIKey(); v != "" {
		cfg.APIKey = v
	}

	if cfg.ControlplaneURL == "" {
		cfg.ControlplaneURL = DefaultControlplaneURL
	}
	cfg.ControlplaneURL = strings.TrimRight(cfg.ControlplaneURL, "/")

	return Result{Config: cfg, Path: path, Diagnostic: diagnostic}, nil
}

// EnvAdminAPIKey returns the admin key override from the environment.
// TINFOIL_ADMIN_KEY takes precedence. TINFOIL_API_KEY is shared with the
// inference SDKs and commonly holds a tk_ key, so it only counts when it
// actually carries an admin key; otherwise the saved login stays in effect.
func EnvAdminAPIKey() string {
	if v := strings.TrimSpace(os.Getenv(EnvAdminKey)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(EnvAPIKey)); strings.HasPrefix(v, AdminKeyPrefix) {
		return v
	}
	return ""
}

func Save(cfg Config) (string, error) {
	path, err := Path()
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

	if err := statefile.Replace(path, append(data, '\n')); err != nil {
		return path, fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

func Delete() (string, bool, error) {
	path, err := Path()
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
