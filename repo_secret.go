package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	repoCmd.AddCommand(repoSecretCmd)
	repoSecretCmd.AddCommand(
		repoSecretListCmd,
		repoSecretGetCmd,
		repoSecretCreateCmd,
		repoSecretSetCmd,
		repoSecretDeleteCmd,
	)
	for _, cmd := range []*cobra.Command{repoSecretCreateCmd, repoSecretSetCmd} {
		cmd.Flags().StringVar(&secretValue, "value", "", "Secret value (use --value-file or stdin to avoid leaking via process listing)")
		cmd.Flags().StringVar(&secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	}
	silenceUsageRecursive(repoSecretCmd)
}

var repoSecretCmd = &cobra.Command{
	Use:     "secret",
	Aliases: []string{"secrets"},
	Short:   "Manage repository-level secrets",
}

var repoSecretListCmd = &cobra.Command{
	Use:     "list [owner/repo]",
	Aliases: []string{"ls"},
	Short:   "List secrets for a repository",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		list, err := listSecrets(client, repository.secretsAPIPath())
		if err != nil {
			return err
		}
		return printSecretList(list)
	},
}

var repoSecretGetCmd = &cobra.Command{
	Use:   "get [owner/repo] [name]",
	Short: "Show repository secret metadata",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		secret, err := getSecret(client, repository.secretAPIPath(args[1]))
		if err != nil {
			return err
		}
		return printSecret(secret)
	},
}

var repoSecretCreateCmd = &cobra.Command{
	Use:   "create [owner/repo] [name]",
	Short: "Create a repository secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		value, err := readSecretValue(cmd)
		if err != nil {
			return err
		}
		secret, err := createSecret(client, repository.secretsAPIPath(), args[1], value)
		if err != nil {
			return err
		}
		fmt.Printf("Created repository secret %s\n", secret.Name)
		return nil
	},
}

var repoSecretSetCmd = &cobra.Command{
	Use:   "set [owner/repo] [name]",
	Short: "Update a repository secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		value, err := readSecretValue(cmd)
		if err != nil {
			return err
		}
		secret, err := setSecret(client, repository.secretAPIPath(args[1]), value)
		if err != nil {
			return err
		}
		fmt.Printf("Updated repository secret %s (matching containers will be marked stale)\n", secret.Name)
		return nil
	},
}

var repoSecretDeleteCmd = &cobra.Command{
	Use:     "delete [owner/repo] [name]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a repository secret",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		if err := deleteSecret(client, repository.secretAPIPath(args[1])); err != nil {
			return err
		}
		fmt.Printf("Deleted repository secret %s\n", args[1])
		return nil
	},
}

func (r repositoryRef) secretsAPIPath() string {
	return pathf("/api/repositories/%s/%s/secrets", r.owner, r.name)
}

func (r repositoryRef) secretAPIPath(name string) string {
	return pathf("/api/repositories/%s/%s/secrets/%s", r.owner, r.name, name)
}
