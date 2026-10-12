package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	// Sandbox creation uses the restricted repository through the container API.
	defaultSandboxRepo = "tinfoilsh/confidential-agent-sandbox"

	sandboxLoginUser = "sandbox"

	sandboxEnrollPath = "/enroll"

	sandboxStateRunning = "running"
	sandboxStateStopped = "stopped"
	sandboxStatePending = "pending"

	// The volume worker requires the same length as volumeKeyBytes in
	// confidential-agent-sandbox.
	sandboxDiskKeyBytes = 64

	// Measured before boot; the workspace key itself stays on this device.
	sandboxOwnerEnv = "SANDBOX_OWNER_KEY_SHA256"

	sandboxKeysDir     = "sandboxes"
	sandboxDiskKeyName = "disk.key"
	sandboxSSHKeyName  = "id_ed25519"

	sandboxBootTimeout = 10 * time.Minute

	sandboxEnrollTimeout = 2 * time.Minute

	maxEnrollReplyBytes = 1 << 12
)

// Restrict names used as local key directories to prevent path traversal.
var sandboxNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

type sandboxView struct {
	ContainerID string `json:"container_id"`
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	State       string `json:"state"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	SSHPort     int    `json:"ssh_port,omitempty"`
}

type sandboxKeys struct {
	dir        string
	diskKey    string
	publicKey  string
	sshKeyPath string
	agentKey   string
	monitor    *monitorAgentConfig
}

var (
	sandboxTag       string
	sandboxVariables []string
	sandboxMonitor   string
	sandboxCreateSSH bool
	sandboxYes       bool
	sandboxSSHStart  bool
	sandboxSSHStop   bool
)

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	sandboxCmd.PersistentFlags().StringArrayVar(&sandboxVariables, "variable", nil, "Expected config environment override in KEY=VALUE form; repeat for each override when creating or connecting")

	sandboxCmd.AddCommand(
		sandboxListCmd,
		sandboxCreateCmd,
		sandboxStartCmd,
		sandboxRestartCmd,
		sandboxStopCmd,
		sandboxDeleteCmd,
		sandboxEnrollCmd,
		sandboxSSHCmd,
	)
	sandboxCreateCmd.Flags().StringVar(&sandboxTag, "tag", "", "Repository tag or commit to deploy")
	sandboxCreateCmd.Flags().StringVar(&sandboxMonitor, "monitor", "", "Contain the sandbox and connect it through this Monitor (see tinfoil monitor create)")
	sandboxCreateCmd.Flags().BoolVar(&sandboxCreateSSH, "ssh", false, "Open a shell once the sandbox is ready")
	sandboxDeleteCmd.Flags().BoolVar(&sandboxYes, "yes", false, "Skip the confirmation prompt")
	sandboxSSHCmd.Flags().BoolVar(&sandboxSSHStart, "start", false, "Start the sandbox first if it is stopped")
	sandboxSSHCmd.Flags().BoolVar(&sandboxSSHStop, "stop", false, "Stop the sandbox once the session ends")

	silenceUsageRecursive(sandboxCmd)
}

var sandboxCmd = &cobra.Command{
	Use:          "sandbox",
	Aliases:      []string{"sandboxes"},
	Short:        "Manage your confidential sandboxes",
	SilenceUsage: true,
}

var sandboxListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List your sandboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var rows []containerView
		if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
			return err
		}
		list := []sandboxView{}
		for _, row := range rows {
			if row.Repo == defaultSandboxRepo && !row.Debug {
				list = append(list, sandboxFromContainer(row))
			}
		}
		return renderSandboxes(list)
	},
}

var sandboxCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a sandbox and enroll this machine's keys into it",
	Long: `Create a sandbox with this device's owner key bound into its boot config,
wait for it to boot, then enroll its workspace.

The keys are made before the first boot and kept in ~/.tinfoil/sandboxes/<name>. Keep
the disk key: it is what the workspace is encrypted with, and without it the
workspace cannot be opened again.

--monitor contains the sandbox: it reaches only that Monitor, and this machine
reaches it through the Monitor with a native ssh profile, so ` + "`ssh <name>`" + `
works afterwards. Its agent key joins the Monitor with no account access. --ssh
opens a shell once the sandbox is ready. Run it again to finish an interrupted
creation: it reuses the keys here and enrolls the running sandbox's current boot.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		variables, err := parseKeyValues(sandboxVariables)
		if err != nil {
			return err
		}
		if variables == nil {
			variables = make(map[string]string)
		}
		body := map[string]any{"name": name, "repo": defaultSandboxRepo, "tag": sandboxTag, "variables": variables}
		resume := false
		if sandboxMonitor != "" {
			if resume, err = registerSandboxAgent(name, sandboxMonitor); err != nil {
				return err
			}
			client, err := authedClient()
			if err != nil {
				return err
			}
			peer, err := containerNamed(client, sandboxMonitor)
			if err != nil {
				return err
			}
			body["network_policy"] = containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{peer.ID, 22}}}
		}
		if _, err := ensureSandboxKeys(name); err != nil {
			return err
		}
		owner, err := loadDiskKey(name)
		if err != nil {
			return err
		}
		variables[sandboxOwnerEnv] = storageHash(owner)
		clear(owner)
		var box *sandboxView
		if resume {
			// Retry enrollment against the existing boot's measured owner key.
			existing, lookupErr := getSandbox(name)
			if lookupErr != nil {
				return lookupErr
			}
			box, err = claimBoot("GET", pathf("/api/containers/%s", existing.ContainerID), name, nil)
		} else {
			if sandboxTag == "" {
				return errors.New("--tag is required when creating a sandbox")
			}
			box, err = bootSandbox("POST", "/api/containers", name, body)
		}
		if err := renderSandbox(box, err); err != nil || !sandboxCreateSSH {
			return err
		}
		return sandboxShell(name, nil)
	},
}

var sandboxStartCmd = &cobra.Command{
	Use:   "start [name]",
	Short: "Start a stopped sandbox and enroll this machine's keys into it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return renderSandbox(startSandbox(name))
	},
}

var sandboxRestartCmd = &cobra.Command{
	Use:   "restart [name]",
	Short: "Restart a sandbox and enroll this machine's keys into it",
	Long: `Restart a sandbox with its saved owner binding, then enroll the new boot
using this device's workspace key.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		if _, err := loadSandboxKeys(name); err != nil {
			return err
		}
		if _, err := stopSandbox(name); err != nil {
			return err
		}
		return renderSandbox(startSandbox(name))
	},
}

var sandboxStopCmd = &cobra.Command{
	Use:   "stop [name]",
	Short: "Stop a sandbox, keeping its workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return renderSandbox(stopSandbox(name))
	},
}

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a sandbox, keeping its workspace volume",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		dir, err := sandboxKeyDir(name)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleting %s frees its name. Its encrypted workspace volume stays, and is billed, until `tinfoil volume delete` removes it.\n", name)
		fmt.Fprintf(os.Stderr, "Keep the keys in %s: that volume cannot be opened without them.\n", dir)
		fmt.Fprintln(os.Stderr)
		if err := confirmYes(sandboxYes, "sandbox delete"); err != nil {
			return err
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		// A retry after a partial delete finds the sandbox gone but its access not yet removed.
		box, err := getSandbox(name)
		if err == nil {
			_, err = client.do("DELETE", pathf("/api/containers/%s", box.ContainerID), nil, nil, nil)
		}
		var missing *cpError
		if err != nil && (!errors.As(err, &missing) || missing.Status != http.StatusNotFound) {
			return err
		}
		contained, forgetErr := forgetContainedSandbox(name)
		switch {
		case forgetErr != nil:
			return fmt.Errorf("%s is deleted, but %w", name, forgetErr)
		case contained:
			fmt.Printf("Deleted %s, its ssh profile and its Monitor identity. Its keys stay in %s.\n", name, dir)
			return nil
		case err != nil:
			return err
		}
		fmt.Printf("Deleted %s. Its keys stay in %s.\n", name, dir)
		return nil
	},
}

var sandboxEnrollCmd = &cobra.Command{
	Use:   "enroll [name]",
	Short: "Attest and enroll this machine's keys into a running sandbox",
	Long: `Verify the current boot and its owner binding, then send the saved
workspace and login keys through an authenticated private connection. When a
Monitor is configured, enrollment also supplies its reverse SSH configuration.

Keys live in ~/.tinfoil/sandboxes/<name>. Restore missing keys from a backup
before enrolling an existing workspace. A lost enrollment reply can be retried
without restarting the sandbox.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		box, err := getSandbox(name)
		if err != nil {
			return err
		}
		return enrollSandbox(*box)
	},
}

var sandboxSSHCmd = &cobra.Command{
	Use:   "ssh [name] [-- ssh arguments...]",
	Short: "SSH into a sandbox with its enrolled key",
	Long: `Open a shell in a sandbox over its attested TLS connection.

This is ` + "`tinfoil ssh`" + ` pointed at the sandbox's domain with the key
enrolled into it, so it works only after an enrollment on the current boot.
A sandbox bound to a Monitor is reached through the Monitor instead, with the
native ssh profile this rewrites first. Anything after -- is handed to ssh
unchanged.

--start boots a stopped sandbox and enrolls into it before connecting. --stop
stops it once the session ends, which takes down everything running in it,
including anything another session left behind.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sshArgs := []string{}
		if dash := cmd.ArgsLenAtDash(); dash >= 0 {
			sshArgs, args = args[dash:], args[:dash]
		}
		if len(args) != 1 {
			return fmt.Errorf("name one sandbox, got %d arguments", len(args))
		}
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return sandboxShell(name, sshArgs)
	},
}

// sandboxShell runs ssh in a sandbox and exits with its status.
func sandboxShell(name string, sshArgs []string) error {
	target, err := sandboxTunnelTarget(name)
	if err != nil {
		return err
	}
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, sandboxSSHKeyName)
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("no SSH key for %s in %s: restore this sandbox's saved keys before enrolling", name, dir)
	}

	options, command := splitSSHArgs(sshArgs)
	// Do not waste the sandbox's three authentication attempts on agent keys.
	options = append([]string{"-i", keyPath, "-o", "IdentitiesOnly=yes"}, options...)
	code, err := runSSH(target, defaultSSHPort, sandboxLoginUser, options, command)
	if sandboxSSHStop {
		if _, stopErr := stopSandbox(name); stopErr != nil {
			err = errors.Join(err, stopErr)
		}
	}
	return sshExit(code, err)
}

func bootSandbox(method, path, name string, body any) (*sandboxView, error) {
	fmt.Fprintf(os.Stderr, "Booting %s. A cold boot takes a few minutes.\n", name)
	return claimBoot(method, path, name, body)
}

// claimBoot starts a container, attests and enrolls it, then installs SSH.
func claimBoot(method, path, name string, body any) (*sandboxView, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	if _, err := loadSandboxKeys(name); err != nil {
		return nil, err
	}
	client.http.Timeout = sandboxBootTimeout

	var row containerView
	if _, err := client.do(method, path, nil, body, &row); err != nil {
		return nil, err
	}
	row, err = waitSandboxContainer(client, row, statusRunning)
	if err != nil {
		return nil, err
	}
	box := sandboxFromContainer(row)

	if err := enrollSandbox(box); err != nil {
		return nil, fmt.Errorf("%s booted but no key was enrolled into it: %w", name, err)
	}
	if err := installSandboxProfile(box); err != nil {
		return nil, fmt.Errorf("%s booted and was enrolled, but its ssh profile was not installed: %w; `tinfoil sandbox ssh %s` still works", name, err, name)
	}
	return &box, nil
}

// Only a quote for this owner's measured boot config can supply the host key.
func installSandboxProfile(box sandboxView) error {
	access, err := sandboxAccessFor(box.ID)
	if err != nil {
		return err
	}
	if access.Contained {
		_, err := containedTarget(box, access)
		return err
	}
	if box.SSHPort == 0 {
		fmt.Fprintf(os.Stderr, "%s offers no direct SSH port, so no native ssh profile was installed\n", box.ID)
		return nil
	}
	keys, err := loadSandboxKeys(box.ID)
	if err != nil {
		return err
	}
	hostKey, client, err := privateSandboxClient(box)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	return sshProfile{name: box.ID, hostName: managedSSHHost, port: box.SSHPort, user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: hostKey}.install()
}

func startSandbox(name string) (*sandboxView, error) {
	if _, err := loadSandboxKeys(name); err != nil {
		return nil, err
	}
	box, err := getSandbox(name)
	if err != nil {
		return nil, err
	}
	method, path := "POST", pathf("/api/containers/%s/deploy", box.ContainerID)
	if box.State == sandboxStateRunning || box.State == sandboxStatePending {
		method, path = "GET", pathf("/api/containers/%s", box.ContainerID)
	}
	return bootSandbox(method, path, name, nil)
}

func waitSandboxContainer(client *cpClient, row containerView, status string) (containerView, error) {
	deadline := time.Now().Add(sandboxBootTimeout)
	for row.Status != status {
		if row.Status == "failed" || time.Now().After(deadline) {
			return row, fmt.Errorf("sandbox %s is %s: %s", row.Name, row.Status, row.ErrorMessage)
		}
		time.Sleep(2 * time.Second)
		if _, err := client.do("GET", pathf("/api/containers/%s", row.ID), nil, nil, &row); err != nil {
			return row, err
		}
	}
	return row, nil
}

func stopSandbox(name string) (*sandboxView, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	box, err := getSandbox(name)
	if err != nil || box.State == sandboxStateStopped {
		return box, err
	}
	var row containerView
	if _, err := client.do("POST", pathf("/api/containers/%s/stop", box.ContainerID), nil, nil, &row); err != nil {
		return nil, err
	}
	row, err = waitSandboxContainer(client, row, statusStopped)
	if err != nil {
		return nil, err
	}
	stopped := sandboxFromContainer(row)
	fmt.Fprintf(os.Stderr, "Stopped %s. It gave up its compute; its workspace and domain stay.\n", name)
	return &stopped, nil
}

// runningSandbox resolves a sandbox to one with a shell to open, booting a
// stopped one only when --start asked for it.
func runningSandbox(name string) (*sandboxView, error) {
	box, err := getSandbox(name)
	if err != nil || box.State == sandboxStateRunning {
		return box, err
	}
	switch box.State {
	case sandboxStateStopped:
		if !sandboxSSHStart {
			return nil, fmt.Errorf("sandbox %s is stopped; start it with `tinfoil sandbox start %s`, or pass --start to start it here", name, name)
		}
		return startSandbox(name)
	case sandboxStatePending:
		return nil, fmt.Errorf("sandbox %s is still booting; wait for the start that is booting it to finish, or restart it with `tinfoil sandbox restart %s` if none is", name, name)
	default:
		return nil, fmt.Errorf("sandbox %s is %s; recover it with `tinfoil sandbox restart %s`", name, box.State, name)
	}
}

func enrollSandbox(box sandboxView) error {
	if box.State != sandboxStateRunning {
		return fmt.Errorf("sandbox %s is %s, so it has no boot to enroll into; start it first", box.ID, box.State)
	}
	if box.Domain == "" {
		return fmt.Errorf("sandbox %s reported no domain, so there is nothing to enroll into", box.ID)
	}
	access, err := sandboxAccessFor(box.ID)
	if err != nil {
		return err
	}
	if access.Contained {
		return enrollContained(box, access)
	}
	keys, err := loadSandboxKeys(box.ID)
	if err != nil {
		return err
	}

	_, httpClient, err := privateSandboxClient(box)
	if err != nil {
		return err
	}
	defer httpClient.CloseIdleConnections()
	if err := sendEnrollment(httpClient, "https://"+box.Domain+sandboxEnrollPath, keys); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Enrolled %s with the keys in %s\n", box.ID, keys.dir)
	fmt.Fprintf(os.Stderr, "Connect with: tinfoil sandbox ssh %s\n", box.ID)
	return nil
}

// sandboxTunnelTarget verifies the measured owner binding before opening a tunnel.
// A stopped sandbox is booted only when --start asks for it.
func sandboxTunnelTarget(name string) (*tunnelTarget, error) {
	if _, err := loadDiskKey(name); err != nil {
		return nil, err
	}
	box, err := runningSandbox(name)
	if err != nil {
		return nil, err
	}
	access, err := sandboxAccessFor(name)
	if err != nil {
		return nil, err
	}
	if access.Contained {
		return containedTarget(*box, access)
	}
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	source, err := sandboxSource(client, *box, sandboxTemplateBase)
	if err != nil {
		return nil, err
	}
	return &tunnelTarget{name: name, host: box.Domain, repo: source}, nil
}

// loadDiskKey never replaces the credential bound into an existing sandbox config.
func loadDiskKey(name string) ([]byte, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, sandboxDiskKeyName)
	saved, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no disk key for %s in %s: restore this sandbox's saved keys before enrolling", name, dir)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(saved)))
	if err != nil || len(key) != sandboxDiskKeyBytes {
		return nil, fmt.Errorf("%s does not hold base64 for a %d-byte workspace key", path, sandboxDiskKeyBytes)
	}
	return key, nil
}

func postEnrollment(httpClient *http.Client, url string, keys *sandboxKeys) error {
	body, _ := json.Marshal(struct {
		Key     string              `json:"key"`
		Volume  string              `json:"volume"`
		Monitor *monitorAgentConfig `json:"monitor,omitempty"`
	}{keys.publicKey, keys.diskKey, keys.monitor})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building enrollment: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollReplyBytes))
	if err != nil {
		return fmt.Errorf("reading the enrollment reply: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("the sandbox refused the enrollment (%s); restore the owner workspace key in %s that was bound when this sandbox was created",
			extractErrorMessage(answer), keys.dir)
	case http.StatusConflict:
		return errors.New("this boot already has an owner enrollment with different values; retry the original enrollment or restart the sandbox")
	default:
		return fmt.Errorf("enrolling: %s: %s", resp.Status, extractErrorMessage(answer))
	}
}

func sandboxRepo() string {
	if repo != "" {
		return repo
	}
	return defaultSandboxRepo
}

func getSandbox(name string) (*sandboxView, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	row, err := containerNamed(client, name)
	if err != nil {
		return nil, err
	}
	if row.Repo != defaultSandboxRepo || row.Debug {
		return nil, fmt.Errorf("container %s is not a sandbox", name)
	}
	box := sandboxFromContainer(row)
	return &box, nil
}

func sandboxFromContainer(row containerView) sandboxView {
	state := row.Status
	if state != statusRunning && state != statusStopped && state != "failed" {
		state = sandboxStatePending
	}
	return sandboxView{ID: row.Name, ContainerID: row.ID, Domain: row.Domain, State: state, SSHPort: row.SSHPort, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func sandboxName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !sandboxNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid sandbox name %q: use letters, digits, dashes or underscores, starting with a letter or digit, up to 63 characters", raw)
	}
	return name, nil
}

func sandboxKeyDir(name string) (string, error) {
	name, err := sandboxName(name)
	if err != nil {
		return "", err
	}
	config, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(config), sandboxKeysDir, name), nil
}

// Enrollment and SSH must restore existing credentials, never generate replacements.
func loadSandboxKeys(name string) (*sandboxKeys, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	owner, err := loadDiskKey(name)
	if err != nil {
		return nil, err
	}
	defer clear(owner)
	path := filepath.Join(dir, sandboxSSHKeyName)
	signer, err := loadSigner(path)
	if err != nil {
		return nil, fmt.Errorf("restore the sandbox login key in %s: %w", path, err)
	}
	return &sandboxKeys{dir: dir, diskKey: base64.StdEncoding.EncodeToString(owner), sshKeyPath: path,
		publicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}, nil
}

func ensureSandboxKeys(name string) (*sandboxKeys, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	keys := &sandboxKeys{dir: dir, sshKeyPath: filepath.Join(dir, sandboxSSHKeyName)}
	if keys.diskKey, err = ensureDiskKey(filepath.Join(dir, sandboxDiskKeyName)); err != nil {
		return nil, err
	}
	if keys.publicKey, err = ensureSSHKey(keys.sshKeyPath); err != nil {
		return nil, err
	}
	return keys, nil
}

// ensureDiskKey never replaces an existing key. A replacement cannot unlock an
// existing workspace.
func ensureDiskKey(path string) (string, error) {
	switch saved, err := os.ReadFile(path); {
	case err == nil:
		key := strings.TrimSpace(string(saved))
		decoded, decodeErr := base64.StdEncoding.DecodeString(key)
		if decodeErr != nil || len(decoded) != sandboxDiskKeyBytes {
			return "", fmt.Errorf("%s does not hold base64 for a %d-byte workspace key; a workspace made with the original key cannot be opened without it, so move this file aside only if you mean to give that up", path, sandboxDiskKeyBytes)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	raw := make([]byte, sandboxDiskKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a workspace key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(raw)
	if err := writeNewFile(path, []byte(key)); err != nil {
		return "", err
	}
	return key, nil
}

func ensureSSHKey(path string) (string, error) {
	saved, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		saved, err = newSSHKey(path)
	}
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(saved)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", path, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func newSSHKey(path string) ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating an SSH key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, fmt.Errorf("encoding an SSH key: %w", err)
	}
	encoded := pem.EncodeToMemory(block)
	if err := writeNewFile(path, encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// writeNewFile uses O_EXCL so concurrent commands cannot replace each other's
// keys.
func writeNewFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		// Half a key reads as a corrupt one, which is a worse thing to find.
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return file.Close()
}

func renderSandbox(from *sandboxView, err error) error {
	if err != nil {
		return err
	}
	box := *from
	if outputFormat == "json" {
		return printJSON(box)
	}
	fmt.Printf("Name:     %s\n", box.ID)
	fmt.Printf("State:    %s\n", box.State)
	fmt.Printf("Domain:   %s\n", box.Domain)
	fmt.Printf("Updated:  %s\n", box.UpdatedAt)
	return nil
}

func renderSandboxes(list []sandboxView) error {
	if outputFormat == "json" {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No sandboxes.")
		return nil
	}
	fmt.Printf("%-24s  %-10s  %-40s  %s\n", "NAME", "STATE", "DOMAIN", "UPDATED")
	for _, box := range list {
		fmt.Printf("%-24s  %-10s  %-40s  %s\n",
			truncate(box.ID, 24), box.State, truncate(box.Domain, 40), box.UpdatedAt,
		)
	}
	return nil
}
