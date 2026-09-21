package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigMalformedFileFallsBackToEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	t.Setenv(envConfigPath, cfgPath)
	t.Setenv(envCPURL, "https://staging.tinfoil.sh")
	t.Setenv(envAdminKey, "")
	t.Setenv(envAPIKey, "admin_env_value")

	cfg, gotPath, err := loadConfig()
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
}

func TestLoadConfigMissingFileUsesEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "missing.json")

	t.Setenv(envConfigPath, cfgPath)
	t.Setenv(envCPURL, "https://staging.tinfoil.sh")
	t.Setenv(envAdminKey, "")
	t.Setenv(envAPIKey, "admin_env_value")

	cfg, _, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig should succeed for missing file, got %v", err)
	}
	if cfg.APIKey != "admin_env_value" {
		t.Fatalf("APIKey = %q, want env override", cfg.APIKey)
	}
	if cfg.ControlplaneURL != "https://staging.tinfoil.sh" {
		t.Fatalf("ControlplaneURL = %q, want env override", cfg.ControlplaneURL)
	}
}

func TestLoadConfigValidFileStillParses(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"controlplane_url":"https://saved.tinfoil.sh","api_key":"admin_saved"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(envConfigPath, cfgPath)
	t.Setenv(envCPURL, "")
	t.Setenv(envAdminKey, "")
	t.Setenv(envAPIKey, "")

	cfg, _, err := loadConfig()
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
			t.Setenv(envConfigPath, cfgPath)
			t.Setenv(envAdminKey, tt.adminKey)
			t.Setenv(envAPIKey, tt.apiKey)

			cfg, _, err := loadConfig()
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.APIKey != tt.want {
				t.Fatalf("APIKey = %q, want %q", cfg.APIKey, tt.want)
			}
		})
	}
}

func TestValidateControlplaneURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		errSubstr string
	}{
		{name: "https default", input: "https://api.tinfoil.sh"},
		{name: "https with port and path", input: "https://api.tinfoil.sh:8443/cp"},
		{name: "https subdomain", input: "https://staging.api.tinfoil.sh"},

		{name: "http localhost", input: "http://localhost:8080"},
		{name: "http 127.0.0.1", input: "http://127.0.0.1:8080"},
		{name: "http ::1", input: "http://[::1]:8080"},

		{name: "empty", input: "", wantError: true, errSubstr: "empty"},
		{name: "no scheme", input: "api.tinfoil.sh", wantError: true, errSubstr: "missing host"},
		{name: "http public", input: "http://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "http with userinfo", input: "http://user:pass@attacker.example.com", wantError: true, errSubstr: "must use https"},
		{name: "ftp", input: "ftp://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "ws", input: "ws://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "https no host", input: "https://", wantError: true, errSubstr: "missing host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateControlplaneURL(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
		})
	}
}
