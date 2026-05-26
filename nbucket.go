package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const (
	nbucketKeyringService = "tinfoil-cli"
	nbucketKeyringAccount = "nbucket-master"
)

func init() {
	rootCmd.AddCommand(nbucketCmd)
	nbucketCmd.AddCommand(nbucketLoginCmd, nbucketLogoutCmd, nbucketWhoamiCmd, nbucketListCmd)
	for _, c := range []*cobra.Command{nbucketCmd, nbucketLoginCmd, nbucketLogoutCmd, nbucketWhoamiCmd, nbucketListCmd} {
		c.SilenceUsage = true
	}
	nbucketLoginCmd.Flags().String("host", "", "named-bucket enclave hostname (default "+defaultNBucketHost+")")
	nbucketLoginCmd.Flags().String("repo", "", "named-bucket source repo (default "+defaultNBucketRepo+")")
	nbucketLoginCmd.Flags().String("api-key", "", "Tinfoil API key (personal). If omitted, prompts on stdin")
}

var nbucketCmd = &cobra.Command{
	Use:   "nbucket",
	Short: "Manage named buckets in your personal Tinfoil account",
	Long: `Verified access to your personal named-bucket account.

Each call performs the same enclave attestation that ` + "`tinfoil http get`" + ` does
(measurement check + Sigstore bundle + TLS pinning) against the named-bucket
enclave before any data leaves your machine.

The master key is stored in the OS keyring (macOS Keychain / Linux Secret
Service / Windows Credential Manager). The API key is stored in
~/.tinfoil/config.json. Both can be overridden per-command via the env vars
TINFOIL_NBUCKET_API_KEY and TINFOIL_NBUCKET_MASTER.`,
}

var nbucketLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Save credentials for a named-bucket account",
	RunE: func(cmd *cobra.Command, args []string) error {
		hostFlag, _ := cmd.Flags().GetString("host")
		repoFlag, _ := cmd.Flags().GetString("repo")
		keyFlag, _ := cmd.Flags().GetString("api-key")

		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}

		nb := cfg.NBucket
		if nb == nil {
			nb = &nbucketConfig{}
		}
		if hostFlag != "" {
			nb.Host = stripScheme(hostFlag)
		}
		if nb.Host == "" {
			nb.Host = defaultNBucketHost
		}
		if repoFlag != "" {
			nb.Repo = repoFlag
		}
		if nb.Repo == "" {
			nb.Repo = defaultNBucketRepo
		}

		apiKey := strings.TrimSpace(keyFlag)
		if apiKey == "" {
			apiKey, err = promptForSecret(fmt.Sprintf("Enter Tinfoil API key for %s: ", nb.Host))
			if err != nil {
				return err
			}
		}
		if apiKey == "" {
			return errors.New("api key is required")
		}
		nb.APIKey = apiKey

		master, err := promptForSecret("Enter bucket master key (base64, 32 bytes): ")
		if err != nil {
			return err
		}
		if master == "" {
			return errors.New("master key is required")
		}

		fmt.Fprintf(os.Stderr, "Verifying %s...\n", nb.Host)
		if err := nbucketVerify(nb, apiKey, master); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}

		if err := keyring.Set(nbucketKeyringService, nbucketKeyringAccount, master); err != nil {
			return fmt.Errorf("storing master key in OS keyring: %w", err)
		}

		cfg.NBucket = nb
		path, err := saveConfig(cfg)
		if err != nil {
			_ = keyring.Delete(nbucketKeyringService, nbucketKeyringAccount)
			return err
		}
		fmt.Printf("Logged in to %s. Config saved to %s (master key in OS keyring).\n", nb.Host, path)
		return nil
	},
}

var nbucketLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored named-bucket credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}
		hadConfig := cfg.NBucket != nil
		cfg.NBucket = nil
		path, err := saveConfig(cfg)
		if err != nil {
			return err
		}

		err = keyring.Delete(nbucketKeyringService, nbucketKeyringAccount)
		hadMaster := err == nil
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "warning: removing master key from keyring: %v\n", err)
		}

		switch {
		case hadConfig && hadMaster:
			fmt.Printf("Removed nbucket config from %s and master key from OS keyring.\n", path)
		case hadConfig:
			fmt.Printf("Removed nbucket config from %s.\n", path)
		case hadMaster:
			fmt.Println("Removed master key from OS keyring.")
		default:
			fmt.Println("No nbucket credentials to remove.")
		}
		return nil
	},
}

var nbucketWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current named-bucket login",
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		fmt.Printf("Host:     %s\n", nb.Host)
		fmt.Printf("Repo:     %s\n", nb.Repo)
		fmt.Printf("API key:  %s\n", redactKey(apiKey))
		fmt.Printf("Master:   %s\n", redactKey(master))

		fmt.Fprintln(os.Stderr, "Verifying enclave and credentials...")
		if err := nbucketVerify(nb, apiKey, master); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		fmt.Println("Status:   authenticated")
		return nil
	},
}

var nbucketListCmd = &cobra.Command{
	Use:   "list",
	Short: "List names in your named-bucket account",
	RunE: func(cmd *cobra.Command, args []string) error {
		nb, apiKey, master, err := requireNBucketAuth()
		if err != nil {
			return err
		}
		names, err := nbucketList(nb, apiKey, master)
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

// nbucketVerify performs a verified GET /list and surfaces 401 specifically so
// the user can tell "wrong master" from generic transport failures.
func nbucketVerify(nb *nbucketConfig, apiKey, master string) error {
	_, err := nbucketList(nb, apiKey, master)
	return err
}

func nbucketList(nb *nbucketConfig, apiKey, master string) ([]string, error) {
	sc := client.NewSecureClient(nb.Host, nb.Repo)
	resp, err := sc.Get("https://"+nb.Host+"/list", map[string]string{
		"Authorization": "Bearer " + apiKey,
		"X-Master-Key":  master,
	})
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, errors.New("master key does not match this account (401)")
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(resp.Body))
	}
	var body struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("decoding /list response: %w", err)
	}
	return body.Names, nil
}

func requireNBucketAuth() (*nbucketConfig, string, string, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return nil, "", "", err
	}
	nb := cfg.NBucket
	if nb == nil {
		nb = &nbucketConfig{}
	}
	if v := strings.TrimSpace(os.Getenv(envNBucketHost)); v != "" {
		nb.Host = stripScheme(v)
	}
	if v := strings.TrimSpace(os.Getenv(envNBucketRepo)); v != "" {
		nb.Repo = v
	}
	apiKey := nb.APIKey
	if v := strings.TrimSpace(os.Getenv(envNBucketAPIKey)); v != "" {
		apiKey = v
	}

	if nb.Host == "" || nb.Repo == "" || apiKey == "" {
		return nil, "", "", fmt.Errorf("not logged in to named-bucket: run `tinfoil nbucket login` or set %s/%s/%s", envNBucketHost, envNBucketAPIKey, envNBucketMaster)
	}

	master := strings.TrimSpace(os.Getenv(envNBucketMaster))
	if master == "" {
		v, err := keyring.Get(nbucketKeyringService, nbucketKeyringAccount)
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return nil, "", "", fmt.Errorf("master key not found in OS keyring — run `tinfoil nbucket login` or set %s", envNBucketMaster)
			}
			return nil, "", "", fmt.Errorf("reading master key from OS keyring: %w", err)
		}
		master = v
	}
	return nb, apiKey, master, nil
}

func stripScheme(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}

func promptForSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", nil
	}
	return strings.TrimSpace(scanner.Text()), nil
}
