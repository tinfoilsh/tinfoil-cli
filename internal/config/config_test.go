package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigMalformedFileFallsBackToEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	t.Setenv(EnvConfigPath, cfgPath)
	t.Setenv(EnvControlplaneURL, "https://staging.tinfoil.sh")
	t.Setenv(EnvAdminKey, "")
	t.Setenv(EnvAPIKey, "admin_env_value")

	result, err := Load()
	cfg, gotPath := result.Config, result.Path
	if err != nil {
		t.Fatalf("loadConfig should succeed despite malformed file, got %v", err)
	}
	if gotPath != cfgPath {
		t.Fatalf("path = %q, want %q", gotPath, cfgPath)
	}
	if cfg.APIKey != "admin_env_value" {
		t.Fatalf("APIKey = %q, want env override to apply", cfg.APIKey)
	}
	if cfg.ControlplaneURL != "https://staging.tinfoil.sh" {
		t.Fatalf("ControlplaneURL = %q, want env override to apply", cfg.ControlplaneURL)
	}
	if result.Diagnostic == nil || !strings.Contains(result.Diagnostic.Error(), "ignoring malformed "+cfgPath) {
		t.Fatalf("diagnostic = %v, want malformed file warning", result.Diagnostic)
	}
}

func TestLoadConfigMissingFileUsesEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "missing.json")

	t.Setenv(EnvConfigPath, cfgPath)
	t.Setenv(EnvControlplaneURL, "https://staging.tinfoil.sh")
	t.Setenv(EnvAdminKey, "")
	t.Setenv(EnvAPIKey, "admin_env_value")

	result, err := Load()
	cfg := result.Config
	if err != nil {
		t.Fatalf("loadConfig should succeed for missing file, got %v", err)
	}
	if cfg.APIKey != "admin_env_value" {
		t.Fatalf("APIKey = %q, want env override", cfg.APIKey)
	}
	if cfg.ControlplaneURL != "https://staging.tinfoil.sh" {
		t.Fatalf("ControlplaneURL = %q, want env override", cfg.ControlplaneURL)
	}
	if result.Diagnostic != nil {
		t.Fatalf("missing file diagnostic = %v", result.Diagnostic)
	}
}

func TestLoadConfigValidFileStillParses(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"controlplane_url":"https://saved.tinfoil.sh","api_key":"admin_saved"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(EnvConfigPath, cfgPath)
	t.Setenv(EnvControlplaneURL, "")
	t.Setenv(EnvAdminKey, "")
	t.Setenv(EnvAPIKey, "")

	result, err := Load()
	cfg := result.Config
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.APIKey != "admin_saved" {
		t.Fatalf("APIKey = %q, want admin_saved", cfg.APIKey)
	}
	if cfg.ControlplaneURL != "https://saved.tinfoil.sh" {
		t.Fatalf("ControlplaneURL = %q, want saved value", cfg.ControlplaneURL)
	}
}

func TestLoadConfigAdminKeyPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"api_key":"admin_saved"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	tests := []struct {
		name     string
		adminKey string
		apiKey   string
		want     string
	}{
		{name: "admin key wins over api key", adminKey: "admin_from_admin_env", apiKey: "admin_from_api_env", want: "admin_from_admin_env"},
		{name: "admin key wins over saved", adminKey: "admin_from_admin_env", want: "admin_from_admin_env"},
		{name: "api key with admin prefix falls back", apiKey: "admin_from_api_env", want: "admin_from_api_env"},
		{name: "inference api key is ignored", apiKey: "tk_inference", want: "admin_saved"},
		{name: "inference api key with admin key", adminKey: "admin_from_admin_env", apiKey: "tk_inference", want: "admin_from_admin_env"},
		{name: "neither set uses saved", want: "admin_saved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvConfigPath, cfgPath)
			t.Setenv(EnvControlplaneURL, "")
			t.Setenv(EnvAdminKey, tt.adminKey)
			t.Setenv(EnvAPIKey, tt.apiKey)

			result, err := Load()
			cfg := result.Config
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.APIKey != tt.want {
				t.Fatalf("APIKey = %q, want %q", cfg.APIKey, tt.want)
			}
		})
	}
}

func TestSavedConfigFormatAndDeletion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfigPath, "")
	t.Setenv(EnvControlplaneURL, "")
	t.Setenv(EnvAdminKey, "")
	t.Setenv(EnvAPIKey, "tk_inference")
	cfg := Config{ControlplaneURL: "https://api.example", APIKey: "admin_saved"}
	path, err := Save(cfg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".tinfoil", "config.json"), path)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "{\n  \"controlplane_url\": \"https://api.example\",\n  \"api_key\": \"admin_saved\"\n}\n", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, 0o600, info.Mode().Perm())
	result, err := Load()
	require.NoError(t, err)
	require.Nil(t, result.Diagnostic)
	require.Equal(t, cfg, result.Config)
	deletedPath, deleted, err := Delete()
	require.NoError(t, err)
	require.Equal(t, path, deletedPath)
	require.True(t, deleted)
	_, deleted, err = Delete()
	require.NoError(t, err)
	require.False(t, deleted)
}

func TestUnreadableConfigReturnsDiagnosticAndEnvironment(t *testing.T) {
	path := t.TempDir()
	t.Setenv(EnvConfigPath, path)
	t.Setenv(EnvControlplaneURL, " https://api.example/// ")
	t.Setenv(EnvAdminKey, " admin_override ")
	result, err := Load()
	require.NoError(t, err)
	require.ErrorContains(t, result.Diagnostic, "cannot read "+path)
	require.Equal(t, Config{ControlplaneURL: "https://api.example", APIKey: "admin_override"}, result.Config)
}
