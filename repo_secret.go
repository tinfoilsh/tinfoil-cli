package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRepoSecretCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoSecretCmd := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets"},
		Short:   "Manage repository-level secrets",
	}
	repoSecretCmd.AddCommand(
		newRepoSecretListCommand(newClient, outputOpts),
		newRepoSecretGetCommand(newClient, outputOpts),
		newRepoSecretCreateCommand(newClient, &secretValueOptions{}),
		newRepoSecretSetCommand(newClient, &secretValueOptions{}),
		newRepoSecretDeleteCommand(newClient),
	)
	return repoSecretCmd
}

func newRepoSecretListCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoSecretListCmd := &cobra.Command{
		Use:     "list [owner/repo]",
		Aliases: []string{"ls"},
		Short:   "List secrets for a repository",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			list, err := listSecrets(client, repository.secretsAPIPath())
			if err != nil {
				return err
			}
			return printSecretList(commandStreams(cmd), outputOpts, list)
		},
	}

	return repoSecretListCmd
}

func newRepoSecretGetCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoSecretGetCmd := &cobra.Command{
		Use:   "get [owner/repo] [name]",
		Short: "Show repository secret metadata",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			secret, err := getSecret(client, repository.secretAPIPath(args[1]))
			if err != nil {
				return err
			}
			return printSecret(commandStreams(cmd), outputOpts, secret)
		},
	}

	return repoSecretGetCmd
}

func newRepoSecretCreateCommand(newClient authenticatedClientFactory, secretValueOpts *secretValueOptions) *cobra.Command {
	repoSecretCreateCmd := &cobra.Command{
		Use:   "create [owner/repo] [name]",
		Short: "Create a repository secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			value, err := readSecretValue(secretValueOpts, cmd)
			if err != nil {
				return err
			}
			secret, err := createSecret(client, repository.secretsAPIPath(), args[1], value)
			if err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Created repository secret %s\n", secret.Name)
			return nil
		},
	}
	repoSecretCreateCmd.Flags().StringVar(&secretValueOpts.secretValue, "value", "", "Secret value (visible in ps; prefer --value-file or stdin)")
	repoSecretCreateCmd.Flags().StringVar(&secretValueOpts.secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	return repoSecretCreateCmd
}

func newRepoSecretSetCommand(newClient authenticatedClientFactory, secretValueOpts *secretValueOptions) *cobra.Command {
	repoSecretSetCmd := &cobra.Command{
		Use:   "set [owner/repo] [name]",
		Short: "Update a repository secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			value, err := readSecretValue(secretValueOpts, cmd)
			if err != nil {
				return err
			}
			secret, err := setSecret(client, repository.secretAPIPath(args[1]), value)
			if err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Updated repository secret %s (matching containers will be marked stale)\n", secret.Name)
			return nil
		},
	}
	repoSecretSetCmd.Flags().StringVar(&secretValueOpts.secretValue, "value", "", "Secret value (visible in ps; prefer --value-file or stdin)")
	repoSecretSetCmd.Flags().StringVar(&secretValueOpts.secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")
	return repoSecretSetCmd
}

func newRepoSecretDeleteCommand(newClient authenticatedClientFactory) *cobra.Command {
	repoSecretDeleteCmd := &cobra.Command{
		Use:     "delete [owner/repo] [name]",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a repository secret",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			if err := deleteSecret(client, repository.secretAPIPath(args[1])); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Deleted repository secret %s\n", args[1])
			return nil
		},
	}

	return repoSecretDeleteCmd
}

func (r repositoryRef) secretsAPIPath() string {
	return pathf("/api/repositories/%s/%s/secrets", r.owner, r.name)
}

func (r repositoryRef) secretAPIPath(name string) string {
	return pathf("/api/repositories/%s/%s/secrets/%s", r.owner, r.name, name)
}
