package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type sshKeyView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	KeyType   string   `json:"key_type"`
	CreatedAt string   `json:"created_at"`
	UsedBy    []string `json:"used_by"`
}

var (
	sshPublicKey     string
	sshPublicKeyFile string
)

func init() {
	rootCmd.AddCommand(sshKeyCmd)
	sshKeyCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	sshKeyCmd.AddCommand(sshKeyListCmd, sshKeyCreateCmd, sshKeyDeleteCmd)

	sshKeyCreateCmd.Flags().StringVar(&sshPublicKey, "public-key", "", "Public key contents (e.g. \"ssh-ed25519 AAAA...\")")
	sshKeyCreateCmd.Flags().StringVar(&sshPublicKeyFile, "public-key-file", "", "Read the public key from this file (use - for stdin)")
	silenceUsageRecursive(sshKeyCmd)
}

var sshKeyCmd = &cobra.Command{
	Use:          "ssh-key",
	Aliases:      []string{"ssh-keys"},
	Short:        "Manage organization SSH public keys (used by debug containers)",
	SilenceUsage: true,
}

var sshKeyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SSH keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var list []sshKeyView
		if _, err := client.do("GET", "/api/ssh-keys", nil, nil, &list); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("No SSH keys.")
			return nil
		}
		fmt.Printf("%-32s  %-12s  %s\n", "NAME", "TYPE", "USED BY")
		for _, k := range list {
			used := strings.Join(k.UsedBy, ", ")
			if used == "" {
				used = "-"
			}
			fmt.Printf("%-32s  %-12s  %s\n", truncate(k.Name, 32), k.KeyType, used)
		}
		return nil
	},
}

var sshKeyCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Add a public SSH key to the organization",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		key, err := readSSHPublicKey(cmd)
		if err != nil {
			return err
		}
		body := map[string]any{"name": args[0], "public_key": key}
		var k sshKeyView
		if _, err := client.do("POST", "/api/ssh-keys", nil, body, &k); err != nil {
			return err
		}
		fmt.Printf("Added SSH key %s (%s)\n", k.Name, k.KeyType)
		return nil
	},
}

var sshKeyDeleteCmd = &cobra.Command{
	Use:     "delete [name]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete an SSH key (fails if any container references it)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/ssh-keys/%s", args[0]), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted SSH key %s\n", args[0])
		return nil
	},
}

func readSSHPublicKey(cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("public-key")
	hasFile := cmd.Flags().Changed("public-key-file")
	if hasInline && hasFile {
		return "", fmt.Errorf("--public-key and --public-key-file are mutually exclusive")
	}
	if hasFile {
		if sshPublicKeyFile == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimSpace(string(data)), nil
		}
		data, err := os.ReadFile(sshPublicKeyFile)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", sshPublicKeyFile, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if hasInline {
		return strings.TrimSpace(sshPublicKey), nil
	}
	return "", fmt.Errorf("provide a public key via --public-key or --public-key-file")
}
