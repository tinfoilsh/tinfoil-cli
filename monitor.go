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
	"github.com/tinfoilsh/tinfoil-go/enclave"
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

	// The control plane waits up to five minutes for a Monitor to boot.
	monitorStartTimeout   = 6 * time.Minute
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
	Domain     string `json:"domain"`
	HostKey    string `json:"host_key,omitempty"`
	Generation uint64 `json:"generation"`
}

var (
	monitorRepin bool
	monitorTag   string
	monitorHost  string
)

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.AddCommand(monitorCreateCmd)
	monitorCreateCmd.Flags().BoolVar(&monitorRepin, "repin", false, "Accept the new attested SSH host key of a restarted Monitor VM")
	monitorCreateCmd.Flags().StringVar(&monitorTag, "tag", "", "Release for a new Monitor (default: latest published stable release)")
	monitorCreateCmd.Flags().StringVar(&monitorHost, "host", "", "Host for a new Monitor (default: organization default)")
	silenceUsageRecursive(monitorCmd)
}

var monitorCmd = &cobra.Command{
	Use:          "monitor",
	Aliases:      []string{"monitors"},
	Short:        "Manage the Monitor your sandboxes connect through",
	SilenceUsage: true,
}

var monitorCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create, start and unlock a Monitor",
	Long: `Create, start or unlock a Monitor. Repeat to resume an interrupted setup.
The controlplane supplies the configuration; attestation verifies its endorsement.
New Monitors use the latest published stable release; --tag selects a specific
release or prerelease. Existing Monitors keep their deployed release.
A signing credential is generated on this device.
Use --repin after a Monitor VM restart, then restart its sandboxes.`,
	Args: cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		scope, client, err := currentScope()
		if err != nil {
			return err
		}
		if err := provisionMonitor(client, scope, name); err != nil {
			return err
		}
		row, err := containerNamed(client, name)
		if err != nil {
			return err
		}
		owner, _, err := connectMonitorOwner(rootCmd.Context(), scope, row, monitorRepin)
		if err != nil {
			return err
		}
		defer owner.Close()
		fmt.Fprintf(os.Stderr, "Monitor %s unlocked.\n", name)
		fmt.Printf("Open the attested local panel: tinfoil monitor open %s\n", name)
		fmt.Printf("Create a sandbox with: tinfoil sandbox create NAME --monitor %s\n", name)
		return nil
	}),
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

// Create credentials before provisioning so retries reuse the same owner.
func provisionMonitor(client *cpClient, scope accountScope, name string) error {
	dir, err := monitorDir(scope, name)
	if err != nil {
		return err
	}
	row, tag, err := workloadRevision(client, name, monitorRepo, monitorTag)
	if err != nil {
		return err
	}
	exists := row.ID != ""
	if exists && monitorHost != "" && monitorHost != row.HostName {
		return fmt.Errorf("%s already uses host %s", name, row.HostName)
	}
	credential, publicKey, err := createOwnerCredential(filepath.Join(dir, monitorOwnerKeyName), exists)
	if err != nil {
		return err
	}
	defer credential.clear()
	if err := prepareStorageDirectory(dir); err != nil {
		return err
	}
	if err := saveOwnerCredential(filepath.Join(dir, monitorOwnerKeyName), credential); err != nil {
		return err
	}
	var saved monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &saved); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	devicePath := filepath.Join(dir, monitorDeviceKeyName)
	if saved.Domain != "" {
		if _, err := loadSSHKey(devicePath); err != nil {
			return fmt.Errorf("restore device key %s: %w", devicePath, err)
		}
	} else if _, err := ensureSSHKey(devicePath); err != nil {
		return err
	}
	if !exists {
		if saved.Domain != "" {
			return errors.New("this name has a saved Monitor profile; use a new name for a new Monitor")
		}
		client.http.Timeout = monitorStartTimeout
		body := map[string]any{"name": name, "repo": monitorRepo, "tag": tag, "variables": map[string]string{monitorOwnerEnv: publicKey}, "object_storage": map[string]string{}}
		if monitorHost != "" {
			body["host_name"] = monitorHost
		}
		_, err = client.do("POST", "/api/containers", nil, body, &row)
		if err != nil {
			return err
		}
	}

	if _, err := workloadSource(row, monitorRepo); err != nil {
		return fmt.Errorf("refusing Monitor %s: %w", name, err)
	}
	environment, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	if environment[monitorOwnerEnv] != publicKey {
		return errors.New("Monitor's measured owner public key does not match the saved credential")
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error {
		if p.Domain == "" {
			p.Domain = row.Domain
		}
		if p.Domain != row.Domain {
			return fmt.Errorf("Monitor %s no longer matches the domain saved in %s", name, dir)
		}

		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Monitor %s: %s@%s\n", name, row.Repo, row.CurrentTag)
	client.http.Timeout = monitorStartTimeout
	if row.Status == "stopped" || row.Status == "failed" {
		if _, err := client.do("POST", pathf("/api/containers/%s/deploy", row.ID), nil, nil, &row); err != nil {
			return err
		}
	}
	row, err = waitWorkload(client, row, statusRunning, monitorStartTimeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Monitor %s running at %s.\n", name, row.Domain)

	return nil
}

// Verify the deployed configuration and preserve the boot-key pin shared with sandboxes.
func verifyMonitor(scope accountScope, row containerView, repin bool) (*enclave.Handle, ssh.PublicKey, error) {
	dir, err := monitorDir(scope, row.Name)
	if err != nil {
		return nil, nil, err
	}
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return nil, nil, err
	}
	if row.Domain != profile.Domain {
		return nil, nil, errors.New("Monitor no longer matches its saved domain")
	}
	source, err := workloadSource(row, monitorRepo)
	if err != nil {
		return nil, nil, err
	}
	secure, err := newVerifiedClient(row.Domain, source, "")
	if err != nil {
		return nil, nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, nil, err
	}
	hostKey, err := endorsedHostKey(row.Domain, verified)
	if err != nil {
		return nil, nil, err
	}
	attested := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	if profile.HostKey != attested {
		if profile.HostKey != "" && !repin {
			return nil, nil, fmt.Errorf("Monitor %s has a new SSH host key; run `tinfoil monitor create %s --repin`, then restart its sandboxes", row.Name, row.Name)
		}
		if _, err := updateProfile(dir, func(p *monitorProfile) error {
			if p.HostKey != profile.HostKey {
				return errors.New("another command changed the pinned Monitor SSH host key; run this again")
			}
			p.HostKey = attested
			return nil
		}); err != nil {
			return nil, nil, err
		}
	}
	return secure, hostKey, nil
}

// SSH authenticates the owner; the storage key only decrypts the state.
func unlockMonitor(client *ssh.Client, dir string, credential *ownerCredential) error {
	return monitorOwnerRequest(client, dir, http.MethodPost, "/unlock", struct {
		StorageKey []byte `json:"storage_key"`
	}{credential.Key}, nil)
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
