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
		var list []secretView
		if _, err := client.do("GET", "/api/secrets", nil, nil, &list); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("No secrets.")
			return nil
		}
		fmt.Printf("%-32s  %-30s  %s\n", "NAME", "UPDATED", "USED BY")
		for _, s := range list {
			used := strings.Join(s.UsedBy, ", ")
			if used == "" {
				used = "-"
			}
			fmt.Printf("%-32s  %-30s  %s\n", truncate(s.Name, 32), truncate(s.UpdatedAt, 30), used)
		}
		return nil
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
		var s secretView
		if _, err := client.do("GET", pathf("/api/secrets/%s", args[0]), nil, nil, &s); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(s)
		}
		fmt.Printf("Name:      %s\n", s.Name)
		fmt.Printf("ID:        %s\n", s.ID)
		fmt.Printf("Created:   %s\n", s.CreatedAt)
		fmt.Printf("Updated:   %s\n", s.UpdatedAt)
		used := strings.Join(s.UsedBy, ", ")
		if used == "" {
			used = "-"
		}
		fmt.Printf("Used by:   %s\n", used)
		return nil
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
		body := map[string]any{"name": args[0], "value": value}
		var s secretView
		if _, err := client.do("POST", "/api/secrets", nil, body, &s); err != nil {
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
		body := map[string]any{"value": value}
		var s secretView
		if _, err := client.do("PUT", pathf("/api/secrets/%s", args[0]), nil, body, &s); err != nil {
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
		if _, err := client.do("DELETE", pathf("/api/secrets/%s", args[0]), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted secret %s\n", args[0])
		return nil
	},
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
