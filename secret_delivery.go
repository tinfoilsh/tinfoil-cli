package main

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

const (
	secretDeliveryManaged          = "managed"
	secretDeliveryPrivateKeyserver = "private_keyserver"
	plannedSecretNamePattern       = `^[A-Za-z_][A-Za-z0-9_-]*$`
	privateSecretSelectionConflict = "private keyserver delivery cannot use selected Tinfoil-managed secrets"
	privateSecretSelectionHint     = `CLI: pass --secret="" on the individual container create, deploy, or update command to send secrets: []. Omission retains saved selections on deploy/update. Project updates cannot clear selections; migrate affected instances individually first. Private names come from measured configuration, not --secret.`
)

var plannedSecretName = regexp.MustCompile(plannedSecretNamePattern)

type plannedSecretDelivery struct {
	Mode                    string   `json:"mode"`
	ManagedSecrets          []string `json:"managed_secrets"`
	ExternalSecrets         []string `json:"external_secrets"`
	ExternalSecretsVerified bool     `json:"external_secrets_verified"`
	KeyserverIgnoredInDebug bool     `json:"keyserver_ignored_in_debug"`
}

func (delivery plannedSecretDelivery) validate(refreshed []string) error {
	invalid := fmt.Errorf("invalid secret delivery in update plan; no update was sent")
	if delivery.ManagedSecrets == nil || delivery.ExternalSecrets == nil || delivery.ExternalSecretsVerified {
		return invalid
	}
	for _, names := range [][]string{delivery.ManagedSecrets, delivery.ExternalSecrets} {
		for _, name := range names {
			if !plannedSecretName.MatchString(name) {
				return invalid
			}
		}
	}
	if !slices.Equal(sortedPlanNames(delivery.ManagedSecrets), sortedPlanNames(refreshed)) {
		return invalid
	}
	switch delivery.Mode {
	case secretDeliveryManaged:
		if len(delivery.ExternalSecrets) != 0 {
			return invalid
		}
	case secretDeliveryPrivateKeyserver:
		if len(delivery.ManagedSecrets) != 0 || delivery.KeyserverIgnoredInDebug {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}

func (plan updatePlan) reviewedSecretDelivery() *plannedSecretDelivery {
	delivery := plannedSecretDelivery{Mode: secretDeliveryManaged, ManagedSecrets: plan.ConfigurationChanges.SecretsRefreshed}
	if plan.SecretDelivery != nil {
		delivery = *plan.SecretDelivery
	}
	delivery.ManagedSecrets = sortedPlanNames(delivery.ManagedSecrets)
	delivery.ExternalSecrets = sortedPlanNames(delivery.ExternalSecrets)
	return &delivery
}

func (delivery plannedSecretDelivery) render(out io.Writer) {
	fmt.Fprintf(out, "  Managed secrets: %s\n  External secrets: %s\n", displayNames(delivery.ManagedSecrets), displayNames(delivery.ExternalSecrets))
	if delivery.Mode == secretDeliveryPrivateKeyserver {
		fmt.Fprintln(out, "  Private keyserver delivery; authorization and unlock are not verified here")
	} else if delivery.KeyserverIgnoredInDebug {
		fmt.Fprintln(out, "  Managed secret delivery; private keyserver endpoint ignored in debug mode.")
	} else {
		fmt.Fprintln(out, "  Managed secret delivery.")
	}
}

func parseSecretSelection(names []string) ([]string, error) {
	if len(names) == 0 || len(names) == 1 && names[0] == "" {
		return []string{}, nil
	}
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf(`--secret: use a single --secret="" to clear managed selections; do not combine an empty value with other selections`)
		}
	}
	return names, nil
}

func secretDeliveryMessage(message string) string {
	if strings.Contains(message, privateSecretSelectionConflict) && !strings.Contains(message, privateSecretSelectionHint) {
		return message + "; " + privateSecretSelectionHint
	}
	return message
}
