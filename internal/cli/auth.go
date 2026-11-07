package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"golang.org/x/term"
)

func newLoginCommand(accounts *accountAccess, openBrowser func(string) error) *cobra.Command {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to Tinfoil",
		Long:  "TINFOIL_ADMIN_KEY (or an admin_ key in TINFOIL_API_KEY) overrides a saved admin key; TINFOIL_CONTROLPLANE_URL overrides its URL.",
		Example: `  Sign in with your browser
  tinfoil login

  Sign in and sync your bunker keys to this machine
  tinfoil login --sync

  Store an admin API key for automation
  tinfoil login --api-key admin_...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			urlFlag, _ := cmd.Flags().GetString("url")
			keyFlag, _ := cmd.Flags().GetString("api-key")
			if keyFlag == "" && urlFlag == "" {
				sync, _ := cmd.Flags().GetBool("sync")
				return accounts.clerkLogin(cmd, sync, openBrowser)
			}

			cfg, _, err := loadConfig(commandStreams(cmd))
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
				key, err = promptSecret(commandStreams(cmd), "api key", fmt.Sprintf("Enter admin API key for %s: ", cfg.ControlplaneURL))
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

			identity, err := accounts.authenticatedContext(commandStreams(cmd), cfg)
			if err != nil {
				return fmt.Errorf("credential check failed: %w", err)
			}

			path, err := saveConfig(cfg)
			if err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Credentials saved to %s\n", path)
			printAuthContext(commandStreams(cmd), "Saved credential", cfg, "file: "+path, identity)
			effective, _, err := loadConfig(commandStreams(cmd))
			if err != nil {
				return err
			}
			if credentialEnvSource() != "" || effective.ControlplaneURL != cfg.ControlplaneURL {
				fmt.Fprintln(commandStreams(cmd).err, "WARNING: environment overrides remain active; the saved credential is not necessarily the effective login.")
				identity, err = accounts.authenticatedContext(commandStreams(cmd), effective)
				if err != nil {
					return fmt.Errorf("credentials saved, but effective environment login could not be verified: %w", err)
				}
			}
			printAuthContext(commandStreams(cmd), "Effective login", effective, credentialSource(), identity)
			accounts.offerRegistryEnrollment(cmd)
			return nil
		},
	}
	loginCmd.Flags().String("url", "", "Controlplane URL for --api-key (default https://api.tinfoil.sh)")
	loginCmd.Flags().String("api-key", "", "Sign in with an admin API key (admin_...) instead of the browser")
	loginCmd.Flags().Bool("sync", false, "Sync your bunker keys to this machine")
	return loginCmd
}

func newLogoutCommand(accounts *accountAccess) *cobra.Command {
	logoutCmd := &cobra.Command{
		Use:   "logout",
		Short: "Sign out and remove saved credentials and synced keys",
		Long:  "Your own SSH keys and locally generated resource keys are kept.",
		RunE: func(cmd *cobra.Command, args []string) error {
			clerkErr := accounts.clerkLogout(commandStreams(cmd))
			path, removed, err := deleteConfig()
			switch {
			case err != nil:
			case !removed:
				fmt.Fprintf(commandStreams(cmd).out, "No saved admin key to remove (%s did not exist)\n", path)
			default:
				fmt.Fprintf(commandStreams(cmd).out, "Removed %s\n", path)
			}
			if source := credentialEnvSource(); source != "" {
				fmt.Fprintf(commandStreams(cmd).err, "WARNING: %s is still active; logout removes only the saved file. Unset %s and any admin key in %s to stop using environment credentials.\n", source, envAdminKey, envAPIKey)
			}
			return errors.Join(clerkErr, err)
		},
	}

	return logoutCmd
}

func newWhoamiCommand(accounts *accountAccess) *cobra.Command {
	whoamiCmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the current login and organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := accounts.requireAuth(commandStreams(cmd))
			if err != nil {
				return err
			}

			identity, err := accounts.authenticatedContext(commandStreams(cmd), cfg)
			if err != nil {
				return fmt.Errorf("verifying credentials: %w", err)
			}
			source := credentialSource()
			if cfg.login != nil {
				source = "Clerk login"
				if dek, err := accounts.syncedKey(commandStreams(cmd), cfg.login, identity.UserID); err != nil || dek == nil {
					source += " (bunker keys not synced)"
				}
			}
			printAuthContext(commandStreams(cmd), "Effective login", cfg, source, identity)
			return nil
		},
	}

	return whoamiCmd
}

func promptSecret(streams commandIO, what, prompt string) (string, error) {
	fmt.Fprint(streams.err, prompt)
	if term.IsTerminal(int(streamFD(streams.in))) {
		raw, err := term.ReadPassword(int(streamFD(streams.in)))
		fmt.Fprintln(streams.err)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		return strings.TrimSpace(string(raw)), nil
	}

	scanner := bufio.NewScanner(streams.in)
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
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
}

func (a *accountAccess) authenticatedContext(streams commandIO, cfg cliConfig) (authContext, error) {
	var identity authContext
	if _, err := a.client(streams, cfg).do("GET", "/api/auth/context", nil, nil, &identity); err != nil {
		return identity, err
	}
	if identity.UserID == "" || identity.ContextType != "personal" && identity.ContextType != "organization" ||
		identity.ContextType == "organization" && (identity.Organization == nil || identity.Organization.ID == "") ||
		identity.ContextType == "personal" && identity.Organization != nil {
		return identity, fmt.Errorf("invalid authenticated context response")
	}
	return identity, nil
}

func randomB64U(n int) string {
	data := make([]byte, n)
	rand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data)
}

func (a *accountAccess) clerkLogin(cmd *cobra.Command, syncKeys bool, openBrowser func(string) error) error {
	service, err := a.auth(commandStreams(cmd))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := service.Login(ctx, syncKeys, auth.LoginProgress{
		Authorize: func(launch string) {
			if !syncKeys {
				fmt.Fprintln(cmd.ErrOrStderr(), "Tip: run `tinfoil login --sync` to also sync your bunker keys.")
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Opening Clerk sign-in. If no browser opens, visit:\n\n  %s\n\nWaiting for sign-in (Ctrl-C cancels)...\n", launch)
			go func() {
				if err := openBrowser(launch); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Could not open your browser: %v\n", err)
				}
			}()
		},
		SignedIn: func(userID, account string) {
			fmt.Fprintf(cmd.OutOrStdout(), "Signed in as %s (account %s).\n", userID, account)
		},
		SyncCode: func(code string) {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nEnter this code in the browser tab that just opened:\n\n    %s\n\nCtrl-C skips key sync and keeps your login.\n", code)
		},
	})
	if err != nil {
		return err
	}
	if result.KeysSynced {
		fmt.Fprintln(cmd.OutOrStdout(), "Bunker keys synced to this machine.")
	}
	a.offerRegistryEnrollment(cmd)
	return nil
}

func (a *accountAccess) clerkLogout(streams commandIO) error {
	service, err := a.auth(streams)
	if err != nil {
		return err
	}
	result, err := service.Logout(context.Background())
	if result.RevocationError != nil {
		fmt.Fprintf(streams.out, "Could not revoke the Clerk login (%v); removing it locally anyway.\n", result.RevocationError)
	}
	if result.Removed {
		fmt.Fprintf(streams.out, "Signed out %s and removed synced keys from this machine.\n", result.UserID)
	}
	return err
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

func printAuthContext(streams commandIO, label string, cfg cliConfig, source string, identity authContext) {
	fmt.Fprintf(streams.out, "%s:\n", label)
	fmt.Fprintf(streams.out, "  Controlplane: %s\n  Credential: %s\n", cfg.ControlplaneURL, source)
	if cfg.APIKey != "" {
		fmt.Fprintf(streams.out, "  API key: %s\n", redactKey(cfg.APIKey))
	}
	fmt.Fprintf(streams.out, "  Context: %s\n", identity.ContextType)
	if identity.Organization != nil {
		fmt.Fprintf(streams.out, "  Organization ID: %s\n", identity.Organization.ID)
		if identity.Organization.Name != "" {
			fmt.Fprintf(streams.out, "  Organization name: %s\n", identity.Organization.Name)
		}
	}
	fmt.Fprintf(streams.out, "  User ID: %s\n", identity.UserID)
}
