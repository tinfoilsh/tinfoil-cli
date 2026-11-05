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

func newSecretCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	secretCmd := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets"},
		Short:   "Manage organization-level secrets",
	}
	secretCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	secretCmd.AddCommand(newSecretListCommand(newClient, outputOpts), newSecretGetCommand(newClient, outputOpts), newSecretCreateCommand(newClient, &secretValueOptions{}), newSecretSetCommand(newClient, &secretValueOptions{}), newSecretDeleteCommand(newClient))
	return secretCmd
}

func newSecretListCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	secretListCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secrets in the organization vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			list, err := listSecrets(client, "/api/secrets")
			if err != nil {
				return err
			}
			return printSecretList(commandStreams(cmd), outputOpts, list)
		},
	}

	return secretListCmd
}

func newSecretGetCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	secretGetCmd := &cobra.Command{
		Use:   "get [name]",
		Short: "Show secret metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			s, err := getSecret(client, pathf("/api/secrets/%s", args[0]))
			if err != nil {
				return err
			}
			return printSecret(commandStreams(cmd), outputOpts, s)
		},
	}

	return secretGetCmd
}

func newSecretCreateCommand(newClient authenticatedClientFactory, secretValueOpts *secretValueOptions) *cobra.Command {
	secretCreateCmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new organization secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			value, err := readSecretValue(secretValueOpts, cmd)
			if err != nil {
				return err
			}
			s, err := createSecret(client, "/api/secrets", args[0], value)
			if err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Created secret %s\n", s.Name)
			return nil
		},
	}
	secretCreateCmd.Flags().StringVar(&secretValueOpts.secretValue, "value", "", "Secret value (visible in ps; prefer --value-file or stdin)")
	secretCreateCmd.Flags().StringVar(&secretValueOpts.secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	return secretCreateCmd
}

func newSecretSetCommand(newClient authenticatedClientFactory, secretValueOpts *secretValueOptions) *cobra.Command {
	secretSetCmd := &cobra.Command{
		Use:   "set [name]",
		Short: "Update the value of an existing secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			value, err := readSecretValue(secretValueOpts, cmd)
			if err != nil {
				return err
			}
			s, err := setSecret(client, pathf("/api/secrets/%s", args[0]), value)
			if err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Updated secret %s (containers using it will be marked stale)\n", s.Name)
			return nil
		},
	}
	secretSetCmd.Flags().StringVar(&secretValueOpts.secretValue, "value", "", "Secret value (visible in ps; prefer --value-file or stdin)")
	secretSetCmd.Flags().StringVar(&secretValueOpts.secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	return secretSetCmd
}

func newSecretDeleteCommand(newClient authenticatedClientFactory) *cobra.Command {
	secretDeleteCmd := &cobra.Command{
		Use:     "delete [name]",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			if err := deleteSecret(client, pathf("/api/secrets/%s", args[0])); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Deleted secret %s\n", args[0])
			return nil
		},
	}

	return secretDeleteCmd
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

func printSecretList(streams commandIO, outputOpts *outputOptions, list []secretView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(streams.out, "No secrets.")
		return nil
	}
	fmt.Fprintf(streams.out, "%-32s  %-30s  %s\n", "NAME", "UPDATED", "USED BY")
	for _, secret := range list {
		used := strings.Join(secret.UsedBy, ", ")
		if used == "" {
			used = "-"
		}
		fmt.Fprintf(streams.out, "%-32s  %-30s  %s\n", truncate(secret.Name, 32), truncate(secret.UpdatedAt, 30), used)
	}
	return nil
}

func printSecret(streams commandIO, outputOpts *outputOptions, secret secretView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, secret)
	}
	fmt.Fprintf(streams.out, "Name:      %s\n", secret.Name)
	fmt.Fprintf(streams.out, "ID:        %s\n", secret.ID)
	fmt.Fprintf(streams.out, "Created:   %s\n", secret.CreatedAt)
	fmt.Fprintf(streams.out, "Updated:   %s\n", secret.UpdatedAt)
	used := strings.Join(secret.UsedBy, ", ")
	if used == "" {
		used = "-"
	}
	fmt.Fprintf(streams.out, "Used by:   %s\n", used)
	return nil
}

// readSecretValue resolves the secret value from --value, --value-file, or
// stdin (when no flags are given but data is piped in).
func readSecretValue(secretValueOpts *secretValueOptions, cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("value")
	hasFile := cmd.Flags().Changed("value-file")

	if hasInline && hasFile {
		return "", fmt.Errorf("--value and --value-file are mutually exclusive")
	}

	if hasFile {
		if secretValueOpts.secretValueFile == "-" {
			data, err := io.ReadAll(commandStreams(cmd).in)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimRight(string(data), "\r\n"), nil
		}
		data, err := os.ReadFile(secretValueOpts.secretValueFile)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", secretValueOpts.secretValueFile, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}

	if hasInline {
		return secretValueOpts.secretValue, nil
	}

	// Fall back to stdin if it's a pipe.
	piped := true
	if file, ok := cmd.InOrStdin().(*os.File); ok {
		stat, err := file.Stat()
		piped = err == nil && (stat.Mode()&os.ModeCharDevice) == 0
	}
	if piped {
		data, err := io.ReadAll(commandStreams(cmd).in)
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
