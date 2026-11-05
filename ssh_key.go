package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type sshKeyView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	KeyType   string   `json:"key_type"`
	PublicKey string   `json:"public_key,omitempty"`
	Sandbox   bool     `json:"sandbox"`
	CreatedAt string   `json:"created_at"`
	UsedBy    []string `json:"used_by"`
}

func newSshKeyCommand(outputOpts *outputOptions, sshKeyOpts *sshKeyOptions) *cobra.Command {
	sshKeyCmd := &cobra.Command{
		Use:     "ssh-key",
		Aliases: []string{"ssh-keys"},
		Short:   "Manage SSH keys",
		Long:    "Container keys open debug containers. Sandbox keys (--sandbox, Ed25519) can own sandboxes and Monitors.",
	}
	sshKeyCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	sshKeyCmd.PersistentFlags().BoolVar(&sshKeyOpts.sshKeySandbox, "sandbox", false, "Use the sandbox and Monitor key list instead of container debug keys")
	sshKeyCmd.AddCommand(newSshKeyListCommand(outputOpts, sshKeyOpts), newSshKeyCreateCommand(sshKeyOpts, &sshKeyCreateOptions{}), newSshKeyDeleteCommand(sshKeyOpts))
	return sshKeyCmd
}

// sshKeyQuery selects the key list; personal accounts always get sandbox keys.
func sshKeyQuery(sshKeyOpts *sshKeyOptions) url.Values {
	if !sshKeyOpts.sshKeySandbox {
		return nil
	}
	return url.Values{"sandbox": {"true"}}
}

func newSshKeyListCommand(outputOpts *outputOptions, sshKeyOpts *sshKeyOptions) *cobra.Command {
	sshKeyListCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List SSH keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if err != nil {
				return err
			}
			var list []sshKeyView
			if _, err := client.do("GET", "/api/ssh-keys", sshKeyQuery(sshKeyOpts), nil, &list); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
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

	return sshKeyListCmd
}

func newSshKeyCreateCommand(sshKeyOpts *sshKeyOptions, sshKeyCreateOpts *sshKeyCreateOptions) *cobra.Command {
	sshKeyCreateCmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Add a public SSH key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if err != nil {
				return err
			}
			key, err := readSSHPublicKey(sshKeyCreateOpts, cmd)
			if err != nil {
				return err
			}
			body := map[string]any{"name": args[0], "public_key": key}
			var k sshKeyView
			if _, err := client.do("POST", "/api/ssh-keys", sshKeyQuery(sshKeyOpts), body, &k); err != nil {
				return err
			}
			fmt.Printf("Added SSH key %s (%s)\n", k.Name, k.KeyType)
			return nil
		},
	}
	sshKeyCreateCmd.Flags().StringVar(&sshKeyCreateOpts.sshPublicKey, "public-key", "", "Public key contents (e.g. \"ssh-ed25519 AAAA...\")")
	sshKeyCreateCmd.Flags().StringVar(&sshKeyCreateOpts.sshPublicKeyFile, "public-key-file", "", "Read the public key from this file (use - for stdin)")
	return sshKeyCreateCmd
}

func newSshKeyDeleteCommand(sshKeyOpts *sshKeyOptions) *cobra.Command {
	sshKeyDeleteCmd := &cobra.Command{
		Use:     "delete [name]",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete an SSH key",
		Long:    "Sandboxes and Monitors that use a deleted sandbox key keep accepting it.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/ssh-keys/%s", args[0]), sshKeyQuery(sshKeyOpts), nil, nil); err != nil {
				return err
			}
			fmt.Printf("Deleted SSH key %s\n", args[0])
			return nil
		},
	}

	return sshKeyDeleteCmd
}

func readSSHPublicKey(sshKeyCreateOpts *sshKeyCreateOptions, cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("public-key")
	hasFile := cmd.Flags().Changed("public-key-file")
	if hasInline && hasFile {
		return "", fmt.Errorf("--public-key and --public-key-file are mutually exclusive")
	}
	if hasFile {
		if sshKeyCreateOpts.sshPublicKeyFile == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimSpace(string(data)), nil
		}
		data, err := os.ReadFile(sshKeyCreateOpts.sshPublicKeyFile)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", sshKeyCreateOpts.sshPublicKeyFile, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if hasInline {
		return strings.TrimSpace(sshKeyCreateOpts.sshPublicKey), nil
	}
	return "", fmt.Errorf("provide a public key via --public-key or --public-key-file")
}
