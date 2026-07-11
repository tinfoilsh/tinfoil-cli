package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type secretView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	UsedBy    []string `json:"used_by"`
}

var (
	secretValue     string
	secretValueFile string
)

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	secretCmd.AddCommand(secretListCmd, secretGetCmd, secretCreateCmd, secretSetCmd, secretDeleteCmd)

	for _, cmd := range []*cobra.Command{secretCreateCmd, secretSetCmd} {
		cmd.Flags().StringVar(&secretValue, "value", "", "Secret value (use --value-file or stdin to avoid leaking via process listing)")
		cmd.Flags().StringVar(&secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	}
	silenceUsageRecursive(secretCmd)
}

var secretCmd = &cobra.Command{
	Use:          "secret",
	Aliases:      []string{"secrets"},
	Short:        "Manage organization-level secrets",
	SilenceUsage: true,
}

var secretListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List secrets in the organization vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		list, err := listSecrets(client, "/api/secrets")
		if err != nil {
			return err
		}
		return printSecretList(list)
	},
}

var secretGetCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Show secret metadata (the value itself is never returned)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		s, err := getSecret(client, pathf("/api/secrets/%s", args[0]))
		if err != nil {
			return err
		}
		return printSecret(s)
	},
}

var secretCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new organization secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		value, err := readSecretValue(cmd)
		if err != nil {
			return err
		}
		s, err := createSecret(client, "/api/secrets", args[0], value)
		if err != nil {
			return err
		}
		fmt.Printf("Created secret %s\n", s.Name)
		return nil
	},
}

var secretSetCmd = &cobra.Command{
	Use:   "set [name]",
	Short: "Update the value of an existing secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		value, err := readSecretValue(cmd)
		if err != nil {
			return err
		}
		s, err := setSecret(client, pathf("/api/secrets/%s", args[0]), value)
		if err != nil {
			return err
		}
		fmt.Printf("Updated secret %s (containers using it will be marked stale)\n", s.Name)
		return nil
	},
}

var secretDeleteCmd = &cobra.Command{
	Use:     "delete [name]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a secret (fails if any container references it)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		if err := deleteSecret(client, pathf("/api/secrets/%s", args[0])); err != nil {
			return err
		}
		fmt.Printf("Deleted secret %s\n", args[0])
		return nil
	},
}

func listSecrets(client *cpClient, path string) ([]secretView, error) {
	var list []secretView
	if _, err := client.do("GET", path, nil, nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func getSecret(client *cpClient, path string) (secretView, error) {
	var secret secretView
	if _, err := client.do("GET", path, nil, nil, &secret); err != nil {
		return secretView{}, err
	}
	return secret, nil
}

func createSecret(client *cpClient, path, name, value string) (secretView, error) {
	var secret secretView
	body := map[string]any{"name": name, "value": value}
	if _, err := client.do("POST", path, nil, body, &secret); err != nil {
		return secretView{}, err
	}
	return secret, nil
}

func setSecret(client *cpClient, path, value string) (secretView, error) {
	var secret secretView
	body := map[string]any{"value": value}
	if _, err := client.do("PUT", path, nil, body, &secret); err != nil {
		return secretView{}, err
	}
	return secret, nil
}

func deleteSecret(client *cpClient, path string) error {
	_, err := client.do("DELETE", path, nil, nil, nil)
	return err
}

func printSecretList(list []secretView) error {
	if outputFormat == "json" {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No secrets.")
		return nil
	}
	fmt.Printf("%-32s  %-30s  %s\n", "NAME", "UPDATED", "USED BY")
	for _, secret := range list {
		used := strings.Join(secret.UsedBy, ", ")
		if used == "" {
			used = "-"
		}
		fmt.Printf("%-32s  %-30s  %s\n", truncate(secret.Name, 32), truncate(secret.UpdatedAt, 30), used)
	}
	return nil
}

func printSecret(secret secretView) error {
	if outputFormat == "json" {
		return printJSON(secret)
	}
	fmt.Printf("Name:      %s\n", secret.Name)
	fmt.Printf("ID:        %s\n", secret.ID)
	fmt.Printf("Created:   %s\n", secret.CreatedAt)
	fmt.Printf("Updated:   %s\n", secret.UpdatedAt)
	used := strings.Join(secret.UsedBy, ", ")
	if used == "" {
		used = "-"
	}
	fmt.Printf("Used by:   %s\n", used)
	return nil
}

// readSecretValue resolves the secret value from --value, --value-file, or
// stdin (when no flags are given but data is piped in).
func readSecretValue(cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("value")
	hasFile := cmd.Flags().Changed("value-file")

	if hasInline && hasFile {
		return "", fmt.Errorf("--value and --value-file are mutually exclusive")
	}

	if hasFile {
		if secretValueFile == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimRight(string(data), "\r\n"), nil
		}
		data, err := os.ReadFile(secretValueFile)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", secretValueFile, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}

	if hasInline {
		return secretValue, nil
	}

	// Fall back to stdin if it's a pipe.
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		v := strings.TrimRight(string(data), "\r\n")
		if v != "" {
			return v, nil
		}
	}

	return "", fmt.Errorf("provide a value via --value, --value-file, or stdin")
}
