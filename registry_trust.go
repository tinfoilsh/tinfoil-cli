package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/term"
)

const registryEnrollmentPath = "/api/config-registry/v2/account"

type registryEnrollment struct {
	ControlplaneURL string   `json:"controlplane_url"`
	AccountID       string   `json:"account_id"`
	Label           string   `json:"label,omitempty"`
	Namespaces      []string `json:"namespaces"`
	Scope           string   `json:"scope"`
}

type registryAccount struct {
	OwnerKind  string   `json:"owner_kind"`
	Namespaces []string `json:"namespaces"`
	Scope      string   `json:"scope"`
}

var enrollmentScope string

func init() {
	trustCmd.AddCommand(trustScopeCmd)
	trustScopeCmd.AddCommand(trustEnrollCmd, trustRemoveCmd, trustScopeListCmd)
	trustEnrollCmd.Flags().StringVar(&enrollmentScope, "scope", "", "Expected audit scope URI; explicitly accepts this scope without a prompt")
}

var trustScopeCmd = &cobra.Command{
	Use: "scope", Short: "Manage private registry scope approvals",
}

var trustScopeListCmd = &cobra.Command{
	Use: "list", Short: "Show approved private registry scopes", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		policy, err := loadConnectionPolicy()
		if err != nil {
			return err
		}
		printRegistryScopes(cmd.OutOrStdout(), policy.Registries)
		return nil
	},
}

var trustEnrollCmd = &cobra.Command{
	Use:   "add",
	Short: "Accept the current account's private registry scope",
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
		return enrollRegistry(cmd, cfg, identity, enrollmentScope, term.IsTerminal(int(os.Stdin.Fd())))
	},
}

var trustRemoveCmd = &cobra.Command{
	Use:   "remove <account-id>",
	Short: "Remove a private registry enrollment for the current control plane",
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
		remaining := slices.DeleteFunc(policy.Registries, func(e registryEnrollment) bool {
			return e.ControlplaneURL == controlplaneURL && e.AccountID == args[0]
		})
		if len(remaining) == len(policy.Registries) {
			return fmt.Errorf("no registry enrollment for account %s", args[0])
		}
		policy.Registries = remaining
		return policy.save()
	},
}

func printRegistryScopes(out io.Writer, entries []registryEnrollment) {
	for _, entry := range entries {
		fmt.Fprintf(out, "Registry: %s (%s) at %s\n  Namespaces: %s\n  Audit scope: %s\n", entry.Label, entry.AccountID, entry.ControlplaneURL, strings.Join(entry.Namespaces, ", "), entry.Scope)
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
		fmt.Fprintf(cmd.ErrOrStderr(), "Signed in, but registry enrollment failed: %v\nRun tinfoil trust scope add to try again.\n", err)
	}
}

func (e registryEnrollment) validate() error {
	if e.AccountID == "" || len(e.Namespaces) == 0 {
		return fmt.Errorf("registry enrollment requires an account and namespaces")
	}
	if err := validateControlplaneURL(e.ControlplaneURL); err != nil {
		return err
	}
	if e.ControlplaneURL != strings.TrimRight(e.ControlplaneURL, "/") {
		return fmt.Errorf("registry controlplane URL must not end with a slash")
	}
	for _, namespace := range e.Namespaces {
		if !strings.HasPrefix(namespace, "/") {
			return fmt.Errorf("registry namespace must start with a slash")
		}
		if err := configendorsement.ValidateIdentityComponent(strings.TrimPrefix(namespace, "/")); err != nil {
			return err
		}
	}
	return configendorsement.ValidateScope(e.Scope)
}

func enrollRegistry(cmd *cobra.Command, cfg cliConfig, identity authContext, expectedScope string, interactive bool) error {
	if !interactive && expectedScope == "" {
		return fmt.Errorf("registry enrollment requires a terminal or an explicit --scope")
	}
	var account registryAccount
	if _, err := newCPClient(cfg).do("GET", registryEnrollmentPath, nil, nil, &account); err != nil {
		return err
	}
	if expectedScope != "" && expectedScope != account.Scope {
		return fmt.Errorf("registry scope does not match the expected scope")
	}
	entry := registryEnrollment{ControlplaneURL: cfg.ControlplaneURL, AccountID: identity.UserID, Label: identity.UserID, Namespaces: account.Namespaces, Scope: account.Scope}
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
	if err := entry.validate(); err != nil {
		return err
	}
	return acceptRegistry(cmd.InOrStdin(), cmd.ErrOrStderr(), entry, expectedScope != "")
}

func acceptRegistry(in io.Reader, out io.Writer, entry registryEnrollment, explicit bool) error {
	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}
	for _, previous := range policy.Registries {
		if previous.ControlplaneURL == entry.ControlplaneURL && previous.AccountID == entry.AccountID && slices.Equal(previous.Namespaces, entry.Namespaces) && previous.Scope == entry.Scope {
			fmt.Fprintf(out, "Registry %s is already enrolled.\n", entry.Label)
			return nil
		}
	}
	fmt.Fprintf(out, "Private registry: %s (%s)\nControl plane: %s\nNamespaces: %s\nAudit scope: %s\n", entry.Label, entry.AccountID, entry.ControlplaneURL, strings.Join(entry.Namespaces, ", "), entry.Scope)
	if !explicit {
		fmt.Fprint(out, "Accept current and future configs in this scope? This replaces any previous enrollment for this account. [y/N] ")
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
	policy.Registries = slices.DeleteFunc(policy.Registries, func(e registryEnrollment) bool {
		return e.ControlplaneURL == entry.ControlplaneURL && e.AccountID == entry.AccountID
	})
	policy.Registries = append(policy.Registries, entry)
	if err := validateRegistryEnrollments(policy.Registries); err != nil {
		return err
	}
	if err := policy.save(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Enrolled %s. Connections in these namespaces require this scope; project and config restrictions still apply.\n", entry.Label)
	return nil
}

func validateRegistryEnrollments(entries []registryEnrollment) error {
	for i, entry := range entries {
		if err := entry.validate(); err != nil {
			return err
		}
		for _, other := range entries[:i] {
			if entry.ControlplaneURL != other.ControlplaneURL {
				continue
			}
			if entry.AccountID == other.AccountID {
				return fmt.Errorf("duplicate registry account enrollment")
			}
			for _, namespace := range entry.Namespaces {
				if slices.Contains(other.Namespaces, namespace) {
					return fmt.Errorf("registry namespace %s has conflicting enrollments", namespace)
				}
			}
		}
	}
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

func registrySigningOptions(source string) ([]verify.Option, error) {
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
	repository, _, _, err := verify.ParseReference(source)
	if err != nil {
		return nil, err
	}
	org, _, _ := strings.Cut(repository, "/")
	for _, entry := range policy.Registries {
		if entry.ControlplaneURL == controlplaneURL && slices.Contains(entry.Namespaces, "/"+org) {
			return []verify.Option{verify.WithConfigScopes(entry.Scope)}, nil
		}
	}
	return nil, nil
}
