package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(loginCmd, logoutCmd, whoamiCmd)
	for _, cmd := range []*cobra.Command{loginCmd, logoutCmd, whoamiCmd} {
		cmd.SilenceUsage = true
	}
	loginCmd.Flags().String("url", "", "Controlplane URL (default https://api.tinfoil.sh)")
	loginCmd.Flags().String("api-key", "", "Admin API key (admin_...). If omitted, prompts on stdin")
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to Tinfoil controlplane with an admin API key",
	Long: `Store credentials for managing Tinfoil containers.

Create an admin API key from the Tinfoil dashboard (Settings → API Keys → Admin keys).
Admin keys select an organization or personal context. The key is stored at
~/.tinfoil/config.json (mode 0600). The TINFOIL_ADMIN_KEY and
TINFOIL_CONTROLPLANE_URL environment variables override the saved values.
TINFOIL_API_KEY is also honored when it holds an admin_ key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		urlFlag, _ := cmd.Flags().GetString("url")
		keyFlag, _ := cmd.Flags().GetString("api-key")

		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}

		if urlFlag != "" {
			cfg.ControlplaneURL = strings.TrimRight(urlFlag, "/")
		}
		if cfg.ControlplaneURL == "" {
			cfg.ControlplaneURL = defaultControlplaneURL
		}
		if err := validateControlplaneURL(cfg.ControlplaneURL); err != nil {
			return err
		}

		key := strings.TrimSpace(keyFlag)
		if key == "" {
			key, err = promptSecret("api key", fmt.Sprintf("Enter admin API key for %s: ", cfg.ControlplaneURL))
			if err != nil {
				return err
			}
		}
		if key == "" {
			return errors.New("api key is required")
		}
		if !strings.HasPrefix(key, adminKeyPrefix) {
			return fmt.Errorf("expected an admin key (prefix %s), got %q", adminKeyPrefix, redactKey(key))
		}

		cfg.APIKey = key

		identity, err := authenticatedContext(cfg)
		if err != nil {
			return fmt.Errorf("credential check failed: %w", err)
		}

		path, err := saveConfig(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("Credentials saved to %s\n", path)
		printAuthContext("Saved credential", cfg, "file: "+path, identity)
		effective, _, err := loadConfig()
		if err != nil {
			return err
		}
		if credentialEnvSource() != "" || effective.ControlplaneURL != cfg.ControlplaneURL {
			fmt.Fprintln(os.Stderr, "WARNING: environment overrides remain active; the saved credential is not necessarily the effective login.")
			identity, err = authenticatedContext(effective)
			if err != nil {
				return fmt.Errorf("credentials saved, but effective environment login could not be verified: %w", err)
			}
		}
		printAuthContext("Effective login", effective, credentialSource(), identity)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored Tinfoil credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, removed, err := deleteConfig()
		if err != nil {
			return err
		}
		if !removed {
			fmt.Printf("No credentials to remove (%s did not exist)\n", path)
		} else {
			fmt.Printf("Removed %s\n", path)
		}
		if source := credentialEnvSource(); source != "" {
			fmt.Fprintf(os.Stderr, "WARNING: %s is still active; logout removes only the saved file. Unset %s and any admin key in %s to stop using environment credentials.\n", source, envAdminKey, envAPIKey)
		}
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current login and organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireAuth()
		if err != nil {
			return err
		}

		identity, err := authenticatedContext(cfg)
		if err != nil {
			return fmt.Errorf("verifying credentials: %w", err)
		}
		printAuthContext("Effective login", cfg, credentialSource(), identity)
		return nil
	},
}

func promptSecret(what, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		return strings.TrimSpace(string(raw)), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		return "", fmt.Errorf("no %s provided", what)
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func redactKey(key string) string {
	if len(key) <= 12 {
		return "***"
	}
	return key[:8] + "…" + key[len(key)-4:]
}

type authContext struct {
	ContextType  string `json:"context_type"`
	Organization *struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
	} `json:"organization"`
	UserID string `json:"user_id"`
}

func authenticatedContext(cfg cliConfig) (authContext, error) {
	var identity authContext
	if _, err := newCPClient(cfg).do("GET", "/api/auth/context", nil, nil, &identity); err != nil {
		return identity, err
	}
	if identity.ContextType != "personal" && identity.ContextType != "organization" ||
		identity.ContextType == "organization" && (identity.Organization == nil || identity.Organization.ID == "") ||
		identity.ContextType == "personal" && (identity.Organization != nil || identity.UserID == "") {
		return identity, fmt.Errorf("invalid authenticated context response")
	}
	return identity, nil
}

func credentialEnvSource() string {
	if strings.TrimSpace(os.Getenv(envAdminKey)) != "" {
		return envAdminKey
	}
	if strings.HasPrefix(strings.TrimSpace(os.Getenv(envAPIKey)), adminKeyPrefix) {
		return envAPIKey
	}
	return ""
}

func credentialSource() string {
	if source := credentialEnvSource(); source != "" {
		return source
	}
	path, err := configPath()
	if err != nil {
		return "saved file (path unavailable)"
	}
	return "file: " + path
}

func printAuthContext(label string, cfg cliConfig, source string, identity authContext) {
	fmt.Printf("%s:\n", label)
	fmt.Printf("  Controlplane: %s\n  Credential: %s\n  API key: %s\n", cfg.ControlplaneURL, source, redactKey(cfg.APIKey))
	fmt.Printf("  Context: %s\n", identity.ContextType)
	if identity.Organization != nil {
		fmt.Printf("  Organization ID: %s\n", identity.Organization.ID)
		if identity.Organization.Name != "" {
			fmt.Printf("  Organization name: %s\n", identity.Organization.Name)
		}
	}
	fmt.Printf("  User ID: %s\n", identity.UserID)
}
