package cli

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
		Use:   "remove <namespace>",
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
		fmt.Fprintf(out, "Private registry for projects under %s\n  Control plane: %s\n", strings.Join(entry.Namespaces, ", "), entry.ControlplaneURL)
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
	entry := registryEnrollment{ControlplaneURL: cfg.ControlplaneURL, AccountID: identity.UserID, Namespaces: account.Namespaces, RegistryID: account.RegistryID}
	ownerKind := "user"
	if identity.Organization != nil {
		ownerKind = "organization"
		entry.AccountID = identity.Organization.ID
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
			fmt.Fprintf(out, "Private registry for projects under %s is already trusted.\n", strings.Join(entry.Namespaces, ", "))
			return nil
		}
		if previous.ControlplaneURL == entry.ControlplaneURL && previous.AccountID == entry.AccountID && previous.RegistryID != entry.RegistryID {
			fmt.Fprintln(out, "Private registry identity changed since you last trusted it.")
		}
	}
	printRegistries(out, []registryEnrollment{entry})
	if !explicit {
		fmt.Fprint(out, "Trust configs from this registry? [y/N] ")
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
	fmt.Fprintln(out, "Trusted this private registry.")
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
