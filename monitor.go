package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	// A Monitor's measured config is this repo's template with the owner key
	// digest and storage binding filled in, so the CLI can render it independently.
	monitorTemplateRepo = "tinfoilsh/confidential-agent-monitor"
	monitorTemplateBase = "https://raw.githubusercontent.com"
	monitorTemplateFile = "tinfoil-config.yml"
	monitorOwnerEnv     = "MONITOR_OWNER_KEY_SHA256"
	monitorConfigPrefix = "/tinfoil/containers/"

	monitorOwnerKeyBytes = 32
	monitorOwnerKeyName  = "owner.key"
	monitorDeviceKeyName = "device_ed25519"
	monitorProfileName   = "profile.json"

	deviceIdentityPrefix   = "device-"
	deviceIdentityHexChars = 12
	sandboxIdentityPrefix  = "sandbox-"

	maxMonitorTemplateBytes = 1 << 20
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

// Persist verified config, boot key, minimum generation and device registration.
type monitorProfile struct {
	Scope      accountScope `json:"scope"`
	Name       string       `json:"name"`
	Domain     string       `json:"domain"`
	Source     string       `json:"source"`
	HostKey    string       `json:"host_key,omitempty"`
	Generation uint64       `json:"generation"`
	StorageID  string       `json:"storage_id,omitempty"`
	Device     string       `json:"device,omitempty"`
}

type monitorState struct {
	Generation uint64 `json:"generation"`
	Config     struct {
		Identities map[string]struct {
			Key    string `json:"key"`
			Routes bool   `json:"routes"`
		} `json:"identities"`
	} `json:"config"`
}

var errDeviceUnregistered = errors.New("this device is not registered")

type monitorSession struct {
	dir     string
	profile monitorProfile
	url     string
	http    *http.Client
	owner   []byte
	hostKey ssh.PublicKey
	state   monitorState
}

type monitorExport struct {
	Profile   monitorProfile               `json:"profile"`
	OwnerKey  string                       `json:"owner_key"`
	Sandboxes map[string]map[string]string `json:"sandboxes"`
}

var sandboxRecoveryFiles = []string{sandboxDiskKeyName, sandboxSSHKeyName, sandboxAgentKeyName}

var monitorRepin bool
var monitorTag string
var monitorTemplatePath string

func init() {
	monitorCreateCmd.Flags().StringVar(&monitorTag, "tag", "", "Repository tag or commit to deploy, required for a new Monitor")
	monitorCreateCmd.Flags().StringVar(&monitorTemplatePath, "template", "", "Local tinfoil-config.yml from that tag or commit, for private development")
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.AddCommand(monitorCreateCmd, monitorExportCmd, monitorImportCmd)
	monitorCreateCmd.Flags().BoolVar(&monitorRepin, "repin", false, "Accept the new attested SSH host key of a restarted Monitor VM")
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
Use --tag to select the release for a new Monitor. For private development,
--template supplies tinfoil-config.yml from that revision for local verification.
Use --repin after a Monitor VM restart, then restart its sandboxes.
Back up credentials with tinfoil monitor export.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		scope, client, err := currentScope()
		if err != nil {
			return err
		}
		if err := provisionMonitor(client, scope, name, monitorTemplateBase); err != nil {
			return err
		}
		m, err := openMonitor(scope, name, monitorRepin)
		if err != nil {
			return err
		}
		if err := m.registerDevice(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Monitor %s unlocked, generation %d.\n", name, m.state.Generation)
		fmt.Printf("Monitor app: https://%s/app/\n", m.profile.Domain)
		fmt.Printf("Create a sandbox with: tinfoil sandbox create NAME --tag TAG --monitor %s --ssh\n", name)
		return nil
	},
}

var monitorExportCmd = &cobra.Command{
	Use:   "export [name] [file]",
	Short: "Write a Monitor's owner secret and its sandboxes' keys to a new file",
	Long: `Export the owner secret and sandbox keys. Keep this file private.
Restore it with tinfoil monitor import.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		scope, _, err := currentScope()
		if err != nil {
			return err
		}
		dir, err := monitorDir(scope, name)
		if err != nil {
			return err
		}
		export := monitorExport{Sandboxes: map[string]map[string]string{}}
		if err := readStorageJSON(filepath.Join(dir, monitorProfileName), &export.Profile); err != nil {
			return err
		}
		owner, err := loadOwnerKey(dir)
		if err != nil {
			return err
		}
		export.OwnerKey = base64.StdEncoding.EncodeToString(owner)
		config, err := configPath()
		if err != nil {
			return err
		}
		root := filepath.Join(filepath.Dir(config), sandboxKeysDir)
		entries, err := os.ReadDir(root)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, entry := range entries {
			dir := filepath.Join(root, entry.Name())
			var binding sandboxBinding
			if readStorageJSON(filepath.Join(dir, sandboxBindingName), &binding) != nil || binding != (sandboxBinding{scope, name}) {
				continue
			}
			files := map[string]string{}
			for _, file := range sandboxRecoveryFiles {
				data, err := os.ReadFile(filepath.Join(dir, file))
				if err != nil {
					return err
				}
				files[file] = string(data)
			}
			export.Sandboxes[entry.Name()] = files
		}
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNewFile(args[1], append(data, '\n')); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Exported Monitor %s and %d sandboxes to %s. Keep this file private.\n", name, len(export.Sandboxes), args[1])
		return nil
	},
}

var monitorImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Restore a Monitor's owner secret and its sandboxes' keys",
	Long: `Import credentials for the current account without overwriting different keys.
Then run tinfoil monitor create NAME to register this device.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var export monitorExport
		if err := json.Unmarshal(data, &export); err != nil {
			return fmt.Errorf("%s is not a Monitor export", args[0])
		}
		scope, _, err := currentScope()
		if err != nil {
			return err
		}
		if export.Profile.Scope != scope {
			return fmt.Errorf("%s belongs to another account at %s", args[0], export.Profile.Scope.ControlplaneURL)
		}
		return importMonitor(scope, export)
	},
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
func provisionMonitor(client *cpClient, scope accountScope, name, templateBase string) error {
	dir, err := monitorDir(scope, name)
	if err != nil {
		return err
	}
	owner, err := ensureOwnerKey(client, dir, name)
	if err != nil {
		return err
	}
	// A registered device key is never remade; importing credentials registers a new one.
	devicePath := filepath.Join(dir, monitorDeviceKeyName)
	var saved monitorProfile
	if _, err := os.Stat(devicePath); errors.Is(err, os.ErrNotExist) && readStorageJSON(filepath.Join(dir, monitorProfileName), &saved) == nil && saved.Device != "" {
		return fmt.Errorf("device key %s is missing from %s; restore it or import a backup", saved.Device, dir)
	}
	if _, err := ensureSSHKey(devicePath); err != nil {
		return err
	}
	digest := storageHash(owner)
	row, err := containerNamed(client, name)
	var missing *cpError
	if errors.As(err, &missing) && missing.Status == http.StatusNotFound {
		storage := map[string]string{}
		var previous monitorProfile
		if readErr := readStorageJSON(filepath.Join(dir, monitorProfileName), &previous); readErr == nil {
			if previous.Scope != scope || previous.Name != name {
				return errors.New("saved Monitor belongs to another account")
			}
			storage["id"] = previous.StorageID
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if monitorTag == "" {
			return errors.New("--tag is required when creating a Monitor")
		}
		_, err = client.do("POST", "/api/containers", nil, map[string]any{"name": name, "repo": monitorTemplateRepo, "tag": monitorTag, "variables": map[string]string{monitorOwnerEnv: digest}, "object_storage": storage}, &row)
	}
	if err != nil {
		return err
	}
	if row.Repo != monitorTemplateRepo {
		return fmt.Errorf("refusing Monitor %s: its template comes from %s, not %s", name, row.Repo, monitorTemplateRepo)
	}
	if monitorTag != "" && row.CurrentTag != monitorTag {
		return fmt.Errorf("Monitor %s already uses %s; stop and recreate it to select a different release", name, row.CurrentTag)
	}
	template, err := monitorTemplate(dir, row.CurrentTag, templateBase)
	if err != nil {
		return err
	}

	source, err := verifyMonitorConfig(row, digest, template)
	if err != nil {
		return fmt.Errorf("refusing Monitor %s: %w", name, err)
	}
	if err := restoreFile(filepath.Join(dir, "template-"+storageHash([]byte(row.CurrentTag))+".yml"), template); err != nil {
		return err
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error {
		if p.Source == "" {
			*p = monitorProfile{Scope: scope, Name: name, Domain: row.Domain, Source: source, StorageID: row.ObjectStorage.ID}
		}
		if p.Scope != scope || p.Name != name || p.Domain != row.Domain || p.StorageID != row.ObjectStorage.ID {
			return fmt.Errorf("Monitor %s no longer matches the configuration verified in %s", name, dir)
		}
		if p.Source != source {
			if monitorTag == "" {
				return fmt.Errorf("Monitor %s changed configuration; select its release with --tag and verify its template", name)
			}
			p.Source = source
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Verified Monitor %s: %s@%s\n", name, row.Repo, row.CurrentTag)
	client.http.Timeout = monitorStartTimeout
	if row.Status == "stopped" || row.Status == "failed" {
		if _, err := client.do("POST", pathf("/api/containers/%s/deploy", row.ID), nil, nil, &row); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(monitorStartTimeout)
	for row.Status != statusRunning {
		if row.Status == "failed" {
			return fmt.Errorf("Monitor failed: %s", row.ErrorMessage)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Monitor is still %s", row.Status)
		}
		time.Sleep(2 * time.Second)
		if _, err := client.do("GET", pathf("/api/containers/%s", row.ID), nil, nil, &row); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Monitor %s running at %s.\n", name, row.Domain)

	return nil
}

// Never generate an owner key for an existing Monitor.
func ensureOwnerKey(client *cpClient, dir, name string) ([]byte, error) {
	path := filepath.Join(dir, monitorOwnerKeyName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		_, err := containerNamed(client, name)
		var missing *cpError
		if err == nil {
			return nil, fmt.Errorf("Monitor %s exists; restore credentials with `tinfoil monitor import FILE`", name)
		}
		if !errors.As(err, &missing) || missing.Status != http.StatusNotFound {
			return nil, err
		}
		if err := prepareStorageDirectory(dir); err != nil {
			return nil, err
		}
		key := make([]byte, monitorOwnerKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generating an owner secret: %w", err)
		}
		if err := writeNewFile(path, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
			return nil, err
		}
	}
	return loadOwnerKey(dir)
}

func loadOwnerKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, monitorOwnerKeyName)
	saved, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(saved)))
	if err != nil || len(key) != monitorOwnerKeyBytes {
		return nil, fmt.Errorf("%s does not hold base64 for a %d-byte owner secret", path, monitorOwnerKeyBytes)
	}
	return key, nil
}

// Verify the control plane response against a locally rendered template.
func verifyMonitorConfig(row containerView, ownerDigest string, template []byte) (string, error) {
	if row.ObjectStorage == nil {
		return "", errors.New("Monitor has no object storage binding")
	}
	bucket, err := url.Parse(row.ObjectStorage.BucketURL)
	if err != nil || bucket.Scheme != "s3" || bucket.Host == "" || bucket.User != nil || bucket.Path != "" || bucket.Fragment != "" {
		return "", errors.New("invalid Monitor bucket URL")
	}
	query, err := url.ParseQuery(bucket.RawQuery)
	if err != nil || len(query) != 2 || len(query["region"]) != 1 || len(query["prefix"]) != 1 || query.Get("region") == "" || row.ObjectStorage.ID == "" || !strings.HasSuffix(query.Get("prefix"), "/"+row.ObjectStorage.ID+"/") {
		return "", errors.New("invalid Monitor storage prefix or region")
	}
	endpoint, err := url.Parse(row.ObjectStorage.CredentialsURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/api/deployments/storage-credentials" {
		return "", errors.New("invalid Monitor credential endpoint")
	}
	rendered, err := renderTemplateEnv(template, map[string]string{monitorOwnerEnv: ownerDigest, "TINFOIL_STORAGE_BUCKET": row.ObjectStorage.BucketURL, "AWS_CONTAINER_CREDENTIALS_FULL_URI": row.ObjectStorage.CredentialsURL})
	if err != nil {
		return "", fmt.Errorf("render Monitor template: %w", err)
	}
	if !bytes.Equal([]byte(row.Config), rendered) {
		return "", errors.New("its measured config does not match the template, owner key and storage binding")
	}
	digest := storageHash([]byte(row.Config))
	if row.ConfigName != monitorConfigPrefix+digest {
		return "", errors.New("unexpected Monitor config reference")
	}
	target, err := parseConnectionDescriptor(connectionDescriptor{URL: "https://" + row.Domain, ConfigName: row.ConfigName, ConfigDigest: digest})
	if err != nil {
		return "", err
	}
	return target.source, nil
}

// Attest, check the saved boot-key pin and unlock at the saved generation.
func openMonitor(scope accountScope, name string, repin bool) (*monitorSession, error) {
	dir, err := monitorDir(scope, name)
	if err != nil {
		return nil, err
	}
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileName), &profile); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this device has no credentials for Monitor %s in this account; run `tinfoil monitor create %s`, or restore them with `tinfoil monitor import FILE`", name, name)
	} else if err != nil {
		return nil, err
	}
	if profile.Scope != scope || profile.Name != name {
		return nil, fmt.Errorf("%s belongs to another account or Monitor", dir)
	}
	owner, err := loadOwnerKey(dir)
	if err != nil {
		return nil, err
	}
	secure, err := newVerifiedClient(profile.Domain, profile.Source, "")
	if err != nil {
		return nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w; start a stopped Monitor with `tinfoil monitor create %s`", profile.Domain, err, name)
	}
	hostKey, err := endorsedHostKey(profile.Domain, verified)
	if err != nil {
		return nil, err
	}
	attested := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	if profile.HostKey != attested {
		if profile.HostKey != "" && !repin {
			return nil, fmt.Errorf("Monitor %s has a new SSH host key; run `tinfoil monitor create %s --repin`, then restart its sandboxes", name, name)
		}
		if profile, err = updateProfile(dir, func(p *monitorProfile) error {
			if p.HostKey != profile.HostKey {
				return fmt.Errorf("another command changed the pinned SSH host key of Monitor %s; run this again", name)
			}
			p.HostKey = attested
			return nil
		}); err != nil {
			return nil, err
		}
		if repin {
			fmt.Fprintf(os.Stderr, "Updated Monitor %s host-key pin. Restart its sandboxes.\n", name)
		}
	}
	client, err := secure.HTTPClient()
	if err != nil {
		return nil, err
	}
	client.Timeout = monitorRequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	m := &monitorSession{dir: dir, profile: profile, url: "https://" + profile.Domain, http: client, owner: owner, hostKey: hostKey}
	if err := m.call("/unlock", map[string]uint64{"generation": profile.Generation}); err != nil {
		return nil, err
	}
	return m, nil
}

// Reject rolled-back policy generations before saving the response.
func (m *monitorSession) call(path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, m.url+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(m.owner))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("Monitor %s %s: %w", m.profile.Name, path, err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxMonitorReplyBytes))
	if err != nil {
		return fmt.Errorf("reading Monitor %s %s: %w", m.profile.Name, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Monitor %s refused %s: %s: %s", m.profile.Name, path, resp.Status, extractErrorMessage(reply))
	}
	var state monitorState
	if err := json.Unmarshal(reply, &state); err != nil {
		return fmt.Errorf("decoding Monitor %s %s: %w", m.profile.Name, path, err)
	}
	if state.Generation < m.profile.Generation {
		return fmt.Errorf("Monitor %s returned rolled-back generation %d, older than %d", m.profile.Name, state.Generation, m.profile.Generation)
	}
	m.state = state
	saved, err := updateProfile(m.dir, func(p *monitorProfile) error {
		p.Generation = max(p.Generation, state.Generation)
		return nil
	})
	if err != nil {
		return err
	}
	m.profile.Generation = saved.Generation
	return nil
}

// Serialize updates to preserve boot-key pins and the maximum generation.
func updateProfile(dir string, update func(*monitorProfile) error) (monitorProfile, error) {
	path := filepath.Join(dir, monitorProfileName)
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

func (m *monitorSession) device() (key, name string, err error) {
	key, err = loadSSHKey(filepath.Join(m.dir, monitorDeviceKeyName))
	return key, deviceIdentityPrefix + storageHash([]byte(key))[:deviceIdentityHexChars], err
}

func (m *monitorSession) deviceRoutes() error {
	key, name, err := m.device()
	if err != nil {
		return err
	}
	registered := m.profile.Device == name
	for _, identity := range m.state.Config.Identities {
		if sameSSHKey(identity.Key, key) {
			if identity.Routes {
				return nil
			}
			registered = true
		}
	}
	if !registered {
		return fmt.Errorf("%w with Monitor %s; run `tinfoil monitor create %s`", errDeviceUnregistered, m.profile.Name, m.profile.Name)
	}
	return fmt.Errorf("Monitor %s identity %s was removed or lost route access. Manage access at https://%s/app/ with key:\n%s", m.profile.Name, name, m.profile.Domain, key)
}

// Record registration first so retries cannot undo a later revocation.
func (m *monitorSession) registerDevice() error {
	err := m.deviceRoutes()
	if !errors.Is(err, errDeviceUnregistered) {
		return err
	}
	key, name, err := m.device()
	if err != nil {
		return err
	}
	if _, err := updateProfile(m.dir, func(p *monitorProfile) error { p.Device = name; return nil }); err != nil {
		return err
	}
	m.profile.Device = name
	return m.ensureIdentity(name, key, true)
}

// Add only absent identities; preserve existing grants.
func (m *monitorSession) ensureIdentity(name, key string, routes bool) error {
	for _, identity := range m.state.Config.Identities {
		if sameSSHKey(identity.Key, key) {
			return nil
		}
	}
	if _, taken := m.state.Config.Identities[name]; taken {
		return fmt.Errorf("Monitor %s already has an identity %s with another key; if it is stale, remove it in the Monitor app", m.profile.Name, name)
	}
	value := map[string]any{"key": key, "accounts": map[string]any{}}
	if routes {
		value["routes"] = true
	}
	if err := m.call("/policy/edits", map[string]any{"changes": []map[string]any{{"path": []string{"identities", name}, "value": value}}}); err != nil {
		return err
	}
	if !sameSSHKey(m.state.Config.Identities[name].Key, key) {
		return fmt.Errorf("Monitor %s did not record identity %s", m.profile.Name, name)
	}
	fmt.Fprintf(os.Stderr, "Added Monitor identity %s.\n", name)
	return nil
}

func (m *monitorSession) removeIdentity(name, key string) error {
	identity, ok := m.state.Config.Identities[name]
	if !ok {
		return nil
	}
	if !sameSSHKey(identity.Key, key) {
		return fmt.Errorf("Monitor identity %s holds another key, so it was left in place", name)
	}
	return m.call("/policy/edits", map[string]any{"changes": []map[string]any{{"path": []string{"identities", name}, "delete": true}}})
}

func sameSSHKey(a, b string) bool {
	x, _, _, _, errX := ssh.ParseAuthorizedKey([]byte(a))
	y, _, _, _, errY := ssh.ParseAuthorizedKey([]byte(b))
	return errX == nil && errY == nil && bytes.Equal(x.Marshal(), y.Marshal())
}

// Import missing credentials without replacing existing ones.
func importMonitor(scope accountScope, export monitorExport) error {
	dir, err := monitorDir(scope, export.Profile.Name)
	if err != nil {
		return err
	}
	if err := prepareStorageDirectory(dir); err != nil {
		return err
	}
	if err := restoreFile(filepath.Join(dir, monitorOwnerKeyName), []byte(export.OwnerKey)); err != nil {
		return err
	}
	if _, err := loadOwnerKey(dir); err != nil {
		return err
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error {
		if p.Source != "" && (p.Domain != export.Profile.Domain || p.Source != export.Profile.Source) {
			return fmt.Errorf("%s describes another Monitor", dir)
		}
		local := *p
		*p = export.Profile
		// The pin and a device identity whose key is still here stay this device's own.
		p.Generation, p.Device = max(p.Generation, local.Generation), ""
		if _, err := os.Stat(filepath.Join(dir, monitorDeviceKeyName)); err == nil {
			p.Device = local.Device
		}
		if local.HostKey != "" {
			p.HostKey = local.HostKey
		}
		return nil
	}); err != nil {
		return err
	}
	binding := sandboxBinding{scope, export.Profile.Name}
	for name, files := range export.Sandboxes {
		keyDir, err := sandboxKeyDir(name)
		if err != nil {
			return err
		}
		if err := bindSandbox(keyDir, binding, false); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := prepareStorageDirectory(keyDir); err != nil {
			return err
		}
		for _, file := range sandboxRecoveryFiles {
			if err := restoreFile(filepath.Join(keyDir, file), []byte(files[file])); err != nil {
				return err
			}
		}
		if err := bindSandbox(keyDir, binding, true); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Imported Monitor %s and %d sandboxes. Run `tinfoil monitor create %s`.\n", export.Profile.Name, len(export.Sandboxes), export.Profile.Name)
	return nil
}

func restoreFile(path string, data []byte) error {
	err := writeNewFile(path, data)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	if saved, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(saved, data) {
		return nil
	}
	return fmt.Errorf("%s already holds a different key; move it aside to import this one", path)
}

// Keep the independently checked release template beside the owner credentials.
// A private checkout can supply it without publishing source or GitHub tokens.
func monitorTemplate(dir, tag, base string) ([]byte, error) {
	path := filepath.Join(dir, "template-"+storageHash([]byte(tag))+".yml")
	if monitorTemplatePath != "" {
		return os.ReadFile(monitorTemplatePath)
	}
	if raw, err := os.ReadFile(path); err == nil {
		return raw, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	location := base + "/" + monitorTemplateRepo + "/" + url.PathEscape(tag) + "/" + monitorTemplateFile
	raw, err := fetchUpdateData(context.Background(), &http.Client{Timeout: monitorRequestTimeout}, location, version, maxMonitorTemplateBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching Monitor template: %w; for a private release, pass --template with its local tinfoil-config.yml", err)
	}
	return raw, nil
}
