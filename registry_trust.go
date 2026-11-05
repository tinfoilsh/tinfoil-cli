package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
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

var enrollmentRegistryID string

func newTrustEnrollCommand() *cobra.Command {
	trustEnrollCmd := &cobra.Command{
		Use:   "add",
		Short: "Trust the current account's private registry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := requireAuth()
			if err != nil {
				return err
			}
			identity, err := authenticatedContext(cfg)
			if err != nil {
				return err
			}
			return enrollRegistry(cmd, cfg, identity, enrollmentRegistryID, term.IsTerminal(int(os.Stdin.Fd())))
		},
	}
	trustEnrollCmd.Flags().StringVar(&enrollmentRegistryID, "registry-id", "", "Expected private registry ID; approves it without a prompt")
	return trustEnrollCmd
}

func newTrustRemoveCommand() *cobra.Command {
	trustRemoveCmd := &cobra.Command{
		Use:   "remove <account>",
		Short: "Stop trusting an account's private registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			controlplaneURL, err := registryControlplaneURL()
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

func offerRegistryEnrollment(cmd *cobra.Command) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	cfg, err := requireAuth()
	if err == nil {
		var identity authContext
		identity, err = authenticatedContext(cfg)
		if err == nil {
			err = enrollRegistry(cmd, cfg, identity, "", true)
		}
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Signed in, but private registry approval failed: %v\nRun tinfoil trust add to try again.\n", err)
	}
}

func enrollRegistry(cmd *cobra.Command, cfg cliConfig, identity authContext, expectedRegistryID string, interactive bool) error {
	if !interactive && expectedRegistryID == "" {
		return fmt.Errorf("private registry approval requires a terminal or an explicit --registry-id")
	}
	var account registryAccount
	if _, err := newCPClient(cfg).do("GET", registryEnrollmentPath, nil, nil, &account); err != nil {
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

func registryControlplaneURL() (string, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return "", err
	}
	if cfg.APIKey == "" {
		grant, err := currentGrant()
		if err != nil {
			return "", err
		}
		if grant != nil {
			return fixedAPIOrigin, nil
		}
	}
	return cfg.ControlplaneURL, nil
}

func registryIDs(source string) ([]string, error) {
	policy, err := loadConnectionPolicy()
	if err != nil {
		return nil, err
	}
	if publicRegistry {
		return nil, nil
	}
	controlplaneURL, err := registryControlplaneURL()
	if err != nil {
		return nil, err
	}
	return policy.RegistryIDs(source, controlplaneURL, publicRegistry)
}
