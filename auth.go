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
Admin keys are scoped to a single organization. The key is stored at
~/.tinfoil/config.json (mode 0600). The TINFOIL_API_KEY and
TINFOIL_CONTROLPLANE_URL environment variables override the saved values.`,
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
			key, err = promptForAPIKey(cfg.ControlplaneURL)
			if err != nil {
				return err
			}
		}
		if key == "" {
			return errors.New("api key is required")
		}
		if !strings.HasPrefix(key, "admin_") {
			return fmt.Errorf("expected an admin key (prefix admin_), got %q", redactKey(key))
		}

		cfg.APIKey = key

		if err := verifyCredentials(cfg); err != nil {
			return fmt.Errorf("credential check failed: %w", err)
		}

		path, err := saveConfig(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("Logged in. Credentials saved to %s\n", path)
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
			return nil
		}
		fmt.Printf("Removed %s\n", path)
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

		fmt.Printf("Controlplane: %s\n", cfg.ControlplaneURL)
		fmt.Printf("API key:      %s\n", redactKey(cfg.APIKey))

		// Hit a cheap authenticated endpoint to confirm credentials and reveal
		// the org-scoped host list (which fails 401 if the key is invalid).
		client := newCPClient(cfg)
		var hosts []hostInfo
		if _, err := client.do("GET", "/api/containers/hosts", nil, nil, &hosts); err != nil {
			return fmt.Errorf("verifying credentials: %w", err)
		}
		fmt.Printf("Status:       authenticated (%d host(s) available)\n", len(hosts))
		return nil
	},
}

func promptForAPIKey(controlplaneURL string) (string, error) {
	fmt.Fprintf(os.Stderr, "Enter admin API key for %s: ", controlplaneURL)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading api key: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading api key: %w", err)
		}
		return "", errors.New("no api key provided")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func redactKey(key string) string {
	if len(key) <= 12 {
		return "***"
	}
	return key[:8] + "…" + key[len(key)-4:]
}

func verifyCredentials(cfg cliConfig) error {
	client := newCPClient(cfg)
	_, err := client.do("GET", "/api/containers/hosts", nil, nil, nil)
	return err
}
