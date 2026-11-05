package main

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/trust"
	"golang.org/x/term"
)

const registryEnrollmentPath = "/api/config-registry/v2/account"

type registryEnrollment = trust.Enrollment

type registryAccount struct {
	OwnerKind  string   `json:"owner_kind"`
	Namespaces []string `json:"namespaces"`
	RegistryID string   `json:"scope"`
}

func newTrustEnrollCommand(accounts *accountAccess, trustEnrollOpts *trustEnrollOptions) *cobra.Command {
	trustEnrollCmd := &cobra.Command{
		Use:   "add",
		Short: "Trust the current account's private registry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := accounts.requireAuth(commandStreams(cmd))
			if err != nil {
				return err
			}
			identity, err := accounts.authenticatedContext(commandStreams(cmd), cfg)
			if err != nil {
				return err
			}
			return accounts.enrollRegistry(cmd, cfg, identity, trustEnrollOpts.enrollmentRegistryID, term.IsTerminal(int(streamFD(commandStreams(cmd).in))))
		},
	}
	trustEnrollCmd.Flags().StringVar(&trustEnrollOpts.enrollmentRegistryID, "registry-id", "", "Expected private registry ID; approves it without a prompt")
	return trustEnrollCmd
}

func newTrustRemoveCommand(accounts *accountAccess) *cobra.Command {
	trustRemoveCmd := &cobra.Command{
		Use:   "remove <account>",
		Short: "Stop trusting an account's private registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			controlplaneURL, err := accounts.registryControlplaneURL(commandStreams(cmd))
			if err != nil {
				return err
			}
			policy, err := loadConnectionPolicy()
			if err != nil {
				return err
			}
			return policy.RemoveRegistry(controlplaneURL, args[0])
		},
	}

	return trustRemoveCmd
}

func printRegistries(out io.Writer, entries []registryEnrollment) {
	for _, entry := range entries {
		fmt.Fprintf(out, "Private registry: %s (%s)\n  Control plane: %s\n  Projects under: %s\n", entry.Label, entry.AccountID, entry.ControlplaneURL, strings.Join(entry.Namespaces, ", "))
	}
}

func (a *accountAccess) offerRegistryEnrollment(cmd *cobra.Command) {
	if !term.IsTerminal(int(streamFD(commandStreams(cmd).in))) {
		return
	}
	cfg, err := a.requireAuth(commandStreams(cmd))
	if err == nil {
		var identity authContext
		identity, err = a.authenticatedContext(commandStreams(cmd), cfg)
		if err == nil {
			err = a.enrollRegistry(cmd, cfg, identity, "", true)
		}
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Signed in, but private registry approval failed: %v\nRun tinfoil trust add to try again.\n", err)
	}
}

func (a *accountAccess) enrollRegistry(cmd *cobra.Command, cfg cliConfig, identity authContext, expectedRegistryID string, interactive bool) error {
	if !interactive && expectedRegistryID == "" {
		return fmt.Errorf("private registry approval requires a terminal or an explicit --registry-id")
	}
	var account registryAccount
	if _, err := a.client(commandStreams(cmd), cfg).do("GET", registryEnrollmentPath, nil, nil, &account); err != nil {
		return err
	}
	if expectedRegistryID != "" && expectedRegistryID != account.RegistryID {
		return fmt.Errorf("private registry ID does not match the expected registry ID")
	}
	entry := registryEnrollment{ControlplaneURL: cfg.ControlplaneURL, AccountID: identity.UserID, Label: identity.UserID, Namespaces: account.Namespaces, RegistryID: account.RegistryID}
	if identity.ContextType == "personal" {
		entry.Label = "Personal"
		if identity.UserName != "" {
			entry.Label = identity.UserName
		}
	}
	ownerKind := "user"
	if identity.Organization != nil {
		ownerKind = "organization"
		entry.AccountID, entry.Label = identity.Organization.ID, identity.Organization.Name
		if entry.Label == "" {
			entry.Label = entry.AccountID
		}
	}
	if ownerKind != account.OwnerKind {
		return fmt.Errorf("registry account does not match the logged-in context")
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	return acceptRegistry(cmd.InOrStdin(), cmd.ErrOrStderr(), entry, expectedRegistryID != "")
}

func acceptRegistry(in io.Reader, out io.Writer, entry registryEnrollment, explicit bool) error {
	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}
	for _, previous := range policy.Registries {
		if previous.ControlplaneURL == entry.ControlplaneURL && previous.AccountID == entry.AccountID && slices.Equal(previous.Namespaces, entry.Namespaces) && previous.RegistryID == entry.RegistryID {
			fmt.Fprintf(out, "Private registry %s is already trusted.\nRegistry ID: %s\n", entry.Label, entry.RegistryID)
			return nil
		}
		if previous.ControlplaneURL == entry.ControlplaneURL && previous.AccountID == entry.AccountID && previous.RegistryID != entry.RegistryID {
			fmt.Fprintf(out, "Private registry identity changed.\nPrevious registry ID: %s\n", previous.RegistryID)
		}
	}
	printRegistries(out, []registryEnrollment{entry})
	fmt.Fprintf(out, "Registry ID: %s\n", entry.RegistryID)
	if !explicit {
		fmt.Fprint(out, "Trust configs from this private registry? Existing project and config restrictions still apply. [y/N] ")
		scanner := bufio.NewScanner(in)
		if !scanner.Scan() {
			return scanner.Err()
		}
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if answer != "y" && answer != "yes" {
			return nil
		}
	}
	policy, err = loadConnectionPolicy()
	if err != nil {
		return err
	}
	if err := policy.AcceptRegistry(entry); err != nil {
		return err
	}
	fmt.Fprintf(out, "Trusted private registry: %s.\n", entry.Label)
	return nil
}

func (a *accountAccess) registryControlplaneURL(streams commandIO) (string, error) {
	cfg, _, err := loadConfig(streams)
	if err != nil {
		return "", err
	}
	if cfg.APIKey == "" {
		grant, err := a.currentGrant(streams)
		if err != nil {
			return "", err
		}
		if grant != nil {
			return a.apiOrigin, nil
		}
	}
	return cfg.ControlplaneURL, nil
}

func registryIDs(rootOpts *rootOptions, source string) ([]string, error) {
	policy, err := loadConnectionPolicy()
	if err != nil {
		return nil, err
	}
	if rootOpts.publicRegistry {
		return nil, nil
	}
	controlplaneURL, err := rootOpts.registryOrigin()
	if err != nil {
		return nil, err
	}
	return policy.RegistryIDs(source, controlplaneURL, rootOpts.publicRegistry)
}
