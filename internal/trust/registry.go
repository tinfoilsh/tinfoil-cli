package trust

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

type Enrollment struct {
	ControlplaneURL string   `json:"controlplane_url"`
	AccountID       string   `json:"account_id"`
	Label           string   `json:"label,omitempty"`
	Namespaces      []string `json:"namespaces"`
	RegistryID      string   `json:"registry_id"`
}

func registryAccountMatches(entry Enrollment, account string) bool {
	return account != "" && (entry.AccountID == account || strings.EqualFold(entry.Label, account) || slices.Contains(entry.Namespaces, "/"+strings.TrimPrefix(account, "/")))
}

func (e Enrollment) Validate() error {
	if e.AccountID == "" || len(e.Namespaces) == 0 {
		return fmt.Errorf("registry enrollment requires an account and namespaces")
	}
	if err := controlplane.ValidateURL(e.ControlplaneURL); err != nil {
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
	return configendorsement.ValidateRegistryID(e.RegistryID)
}

func validateRegistryEnrollments(entries []Enrollment) error {
	for i, entry := range entries {
		if err := entry.Validate(); err != nil {
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

func (p *Policy) AcceptRegistry(entry Enrollment) error {
	p.Registries = slices.DeleteFunc(p.Registries, func(e Enrollment) bool {
		return e.ControlplaneURL == entry.ControlplaneURL && e.AccountID == entry.AccountID
	})
	p.Registries = append(p.Registries, entry)
	if err := validateRegistryEnrollments(p.Registries); err != nil {
		return err
	}
	return p.save()
}

func (p *Policy) RemoveRegistry(controlplaneURL, account string) error {
	accountID := ""
	for _, entry := range p.Registries {
		if entry.ControlplaneURL == controlplaneURL && entry.AccountID == account {
			accountID = entry.AccountID
			break
		}
	}
	if accountID == "" {
		for _, entry := range p.Registries {
			if entry.ControlplaneURL == controlplaneURL && registryAccountMatches(entry, account) {
				if accountID != "" {
					return fmt.Errorf("multiple private registries match %s; use the account ID shown by tinfoil trust", account)
				}
				accountID = entry.AccountID
			}
		}
	}
	remaining := slices.DeleteFunc(p.Registries, func(e Enrollment) bool {
		return e.ControlplaneURL == controlplaneURL && e.AccountID == accountID
	})
	if len(remaining) == len(p.Registries) {
		return fmt.Errorf("no registry enrollment for account %s", account)
	}
	p.Registries = remaining
	return p.save()
}

func (p Policy) RegistryIDs(source, controlplaneURL string, public bool) ([]string, error) {
	if public {
		return nil, nil
	}
	repository, _, _, err := verify.ParseReference(source)
	if err != nil {
		return nil, err
	}
	org, _, _ := strings.Cut(repository, "/")
	for _, entry := range p.Registries {
		if entry.ControlplaneURL == controlplaneURL && slices.Contains(entry.Namespaces, "/"+org) {
			return []string{entry.RegistryID}, nil
		}
	}
	return nil, nil
}
