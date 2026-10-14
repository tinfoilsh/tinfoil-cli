package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	monitorRepo     = "tinfoilsh/confidential-agent-monitor"
	monitorOwnerEnv = "MONITOR_OWNER_PUBLIC_KEY"

	monitorOwnerKeyName  = "owner.key"
	monitorDeviceKeyName = "device_ed25519"
	monitorProfileFile   = "profile.json"

	// Monitor's owner API accepts and returns documents up to this size.
	maxMonitorReplyBytes = 16 << 20

	monitorRequestTimeout = time.Minute

	profileLockAttempts = 50
	profileLockRetry    = 20 * time.Millisecond
)

// Monitor names are scoped to an account and control plane.
type accountScope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id,omitempty"`
	UserID          string `json:"user_id"`
}

// Persist the domain, boot key and minimum generation.
type monitorProfile struct {
	Domain      string `json:"domain"`
	Address     string `json:"address,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Owner       string `json:"owner_public_key,omitempty"`
	Storage     string `json:"storage,omitempty"`
	HostKey     string `json:"host_key,omitempty"`
	Generation  uint64 `json:"generation"`
}

func init() { rootCmd.AddCommand(monitorCmd) }

var monitorCmd = &cobra.Command{
	Use:          "monitor",
	Aliases:      []string{"monitors"},
	Short:        "Manage the Monitor your sandboxes connect through",
	SilenceUsage: true,
}

func currentScope() (accountScope, *cpClient, error) {
	cfg, err := requireAuth()
	if err != nil {
		return accountScope{}, nil, err
	}
	identity, err := authenticatedContext(cfg)
	if err != nil {
		return accountScope{}, nil, err
	}
	scope := accountScope{ControlplaneURL: cfg.ControlplaneURL, UserID: identity.UserID}
	if identity.Organization != nil {
		scope.OrgID = identity.Organization.ID
	}
	return scope, newCPClient(cfg), nil
}

func monitorDir(scope accountScope, name string) (string, error) {
	name, err := sandboxName(name)
	if err != nil {
		return "", err
	}
	config, err := configPath()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(config), "monitors", storageHash(data), name), nil
}

// Verify the deployed configuration and preserve the boot-key pin shared with sandboxes.
func verifyMonitor(dir string, row containerView) (ssh.PublicKey, error) {
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return nil, err
	}
	if row.Domain != profile.Domain {
		return nil, errors.New("Monitor no longer matches its saved domain")
	}
	source, err := workloadSource(row, monitorRepo)
	if err != nil {
		return nil, err
	}
	finish := startConnectionProgress(os.Stderr, "Verifying Monitor "+row.Name+" attestation and SSH host key")
	defer finish()
	secure, err := newVerifiedClient(row.Domain, source, "")
	if err != nil {
		return nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, err
	}
	hostKey, err := endorsedHostKey(row.Domain, verified)
	if err != nil {
		return nil, err
	}
	attested := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	if profile.HostKey != attested {
		if _, err := updateProfile(dir, func(p *monitorProfile) error {
			if p.HostKey != profile.HostKey {
				return errors.New("another command changed the pinned Monitor SSH host key; run this again")
			}
			p.HostKey = attested
			return nil
		}); err != nil {
			return nil, err
		}
	}
	finish()
	fmt.Fprintf(os.Stderr, "Monitor %s attestation verified.\n", row.Name)
	return hostKey, nil
}

// SSH authenticates the owner; the storage key only decrypts the state.
func unlockMonitor(client *ssh.Client, dir string, credential *ownerCredential) error {
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return err
	}
	return monitorOwnerRequest(client, dir, http.MethodPost, "/unlock", struct {
		StorageKey []byte `json:"storage_key"`
		Initialize bool   `json:"initialize"`
	}{credential.Key, profile.Generation == 0}, nil)
}

// Serialize updates to preserve boot-key pins and the maximum generation.
func updateProfile(dir string, update func(*monitorProfile) error) (monitorProfile, error) {
	path := filepath.Join(dir, monitorProfileFile)
	unlock, err := acquireStorageLock(path)
	for attempt := 1; err != nil && attempt < profileLockAttempts; attempt++ {
		time.Sleep(profileLockRetry)
		unlock, err = acquireStorageLock(path)
	}
	if err != nil {
		return monitorProfile{}, err
	}
	defer unlock()
	var profile monitorProfile
	if err := readStorageJSON(path, &profile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return profile, err
	}
	if err := update(&profile); err != nil {
		return profile, err
	}
	return profile, writeStorageJSON(path, profile, false)
}
