package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
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

	sandboxStateRunning = "running"
	sandboxStateStopped = "stopped"
	sandboxStatePending = "pending"

	// Only the owner public key enters the measured boot configuration.
	sandboxOwnerEnv = "SANDBOX_OWNER_PUBLIC_KEY"

	sandboxKeysDir     = "sandboxes"
	sandboxDiskKeyName = "disk.key"
	sandboxSSHKeyName  = "owner_ed25519"

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
	dir             string
	diskKey         string
	ownerSeed       []byte
	sshKeyPath      string
	agentKey        string
	monitorIdentity string
}

var (
	sandboxTag string

	sandboxVariables []string
	sandboxMonitor   string
	sandboxYes       bool
)

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	sandboxCreateCmd.Flags().StringArrayVar(&sandboxVariables, "variable", nil, "Config environment override in KEY=VALUE form; repeat for each override when creating")

	sandboxCmd.AddCommand(
		sandboxListCmd,
		sandboxCreateCmd,
		sandboxStartCmd,
		sandboxRestartCmd,
		sandboxStopCmd,
		sandboxDeleteCmd,
		sandboxEnrollCmd,
	)
	sandboxCreateCmd.Flags().StringVar(&sandboxTag, "tag", "", "Release for a new sandbox (default: latest published stable release)")
	sandboxCreateCmd.Flags().StringVar(&sandboxMonitor, "monitor", "", "Required Monitor for sandbox networking (see tinfoil monitor create)")
	sandboxDeleteCmd.Flags().BoolVar(&sandboxYes, "yes", false, "Skip the confirmation prompt")

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

A signing credential is generated on this device. Keys are kept in
~/.tinfoil/sandboxes/<name>. Later commands require these saved keys.
The controlplane supplies the configuration; attestation verifies its endorsement.
New sandboxes use the latest published stable release; --tag selects a specific
release or prerelease. Existing sandboxes keep their deployed release.

--monitor is required. The sandbox reaches only that Monitor, and this machine
reaches it through the Monitor with a native ssh profile, so ` + "`ssh <name>`" + `
works after creation. New sandboxes register their agent key and authorize this
device to open sandbox routes. Grant account access separately in the Monitor UI.
The Monitor must be unlocked and its owner credential saved on this device.
Create, start and enroll install the SSH profile automatically.
Repeat create to finish an interrupted creation: it reuses the keys here and
enrolls the running sandbox's current boot.`,
	Args: cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		if sandboxMonitor == "" {
			return errors.New("--monitor is required; create one with `tinfoil monitor create NAME`")
		}
		if _, err := sandboxName(sandboxMonitor); err != nil {
			return err
		}
		variables, err := parseKeyValues(sandboxVariables)
		if err != nil {
			return err
		}
		if variables == nil {
			variables = make(map[string]string)
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		row, tag, err := workloadRevision(client, name, defaultSandboxRepo, sandboxTag)
		if err != nil {
			return err
		}
		exists := row.ID != ""
		if exists && row.Status != statusRunning {
			return fmt.Errorf("sandbox %s already exists; start it with `tinfoil sandbox start %s`", name, name)
		}
		dir, err := sandboxKeyDir(name)
		if err != nil {
			return err
		}
		credential, publicKey, err := createOwnerCredential(filepath.Join(dir, sandboxDiskKeyName), exists)
		if err != nil {
			return err
		}
		defer credential.clear()
		variables[sandboxOwnerEnv] = publicKey
		body := map[string]any{"name": name, "repo": defaultSandboxRepo, "tag": tag, "variables": variables}
		policy, err := prepareSandboxMonitor(client, row, name, sandboxMonitor, credential, variables)
		if err != nil {
			return err
		}
		body["network_policy"] = policy

		method, path := "POST", "/api/containers"
		if exists {
			method, path, body = "GET", pathf("/api/containers/%s", row.ID), nil
		}
		return renderSandbox(bootSandbox(method, path, name, body))
	}),
}

var sandboxStartCmd = &cobra.Command{
	Use:   "start [name]",
	Short: "Start a stopped sandbox and enroll this machine's keys into it",
	Args:  cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		return renderSandbox(startSandbox(name))
	}),
}

var sandboxRestartCmd = &cobra.Command{
	Use:   "restart [name]",
	Short: "Restart a sandbox and enroll this machine's keys into it",
	Long: `Restart a sandbox with its saved owner binding, then enroll the new boot
using this device's workspace key.`,
	Args: cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		if _, err := loadSandboxKeys(name); err != nil {
			return err
		}
		box, err := getSandbox(name)
		if err != nil {
			return err
		}
		if box.State != "failed" && box.State != sandboxStateStopped {
			if _, err := stopSandbox(name); err != nil {
				return err
			}
		}
		return renderSandbox(startSandbox(name))
	}),
}

var sandboxStopCmd = &cobra.Command{
	Use:   "stop [name]",
	Short: "Stop a sandbox, keeping its workspace",
	Args:  cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		return renderSandbox(stopSandbox(name))
	}),
}

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a sandbox, keeping its workspace volume",
	Args:  cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
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
		// A retry may find the sandbox gone with a local SSH profile still installed.
		box, err := getSandbox(name)
		if err == nil {
			_, err = client.do("DELETE", pathf("/api/containers/%s", box.ContainerID), nil, nil, nil)
		}
		if err != nil && !missingContainer(err) {
			return err
		}
		if err := forgetSandbox(name); err != nil {
			return fmt.Errorf("%s is deleted, but %w", name, err)
		}
		fmt.Printf("Deleted %s and its SSH profile. Its keys stay in %s. Remove any access grants in the Monitor UI.\n", name, dir)
		return nil
	}),
}

var sandboxEnrollCmd = &cobra.Command{
	Use:   "enroll [name]",
	Short: "Attest, enroll and install the SSH profile for a running sandbox",
	Long: `Verify the current boot and its owner binding, then send the saved
workspace key and Monitor agent identity over attested SSH. The login key is
fixed by the measured owner public key at boot. The
Monitor provides the sandbox network and reverse SSH connection.

Keys live in ~/.tinfoil/sandboxes/<name>. A lost enrollment reply can be retried
without restarting the sandbox. This also repairs the local SSH profile.`,
	Args: cobra.ExactArgs(1),
	RunE: namedWorkload(func(name string) error {
		box, err := getSandbox(name)
		if err != nil {
			return err
		}
		return enrollSandbox(*box)
	}),
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
	row, err = waitWorkload(client, row, statusRunning, sandboxBootTimeout)
	if err != nil {
		return nil, err
	}
	box := sandboxFromContainer(row)

	if err := enrollSandbox(box); err != nil {
		return nil, err
	}
	return &box, nil
}

func startSandbox(name string) (*sandboxView, error) {
	keys, err := loadSandboxKeys(name)
	if err != nil {
		return nil, err
	}
	defer clear(keys.ownerSeed)
	scope, client, err := currentScope()
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
	if row.Status != statusStopped && row.Status != "failed" {
		return bootSandbox("GET", pathf("/api/containers/%s", row.ID), name, nil)
	}
	var binding sandboxBinding
	if err := readStorageJSON(filepath.Join(keys.dir, sandboxBindingName), &binding); err != nil {
		return nil, err
	}
	if binding.Scope != scope {
		return nil, errors.New("sandbox keys belong to another account")
	}
	peer, err := containerNamed(client, binding.Monitor)
	if err != nil {
		return nil, err
	}
	variables, err := decodeContainerVariables(row.Variables)
	if err != nil {
		return nil, err
	}
	if variables == nil {
		variables = map[string]string{}
	}
	if err := sandboxBootMonitor(scope, peer, variables); err != nil {
		return nil, err
	}
	return bootSandbox("POST", pathf("/api/containers/%s/deploy", row.ID), name, map[string]any{"variables": variables})
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
	row, err = waitWorkload(client, row, statusStopped, sandboxBootTimeout)
	if err != nil {
		return nil, err
	}
	stopped := sandboxFromContainer(row)
	fmt.Fprintf(os.Stderr, "Stopped %s. It gave up its compute; its workspace and domain stay.\n", name)
	return &stopped, nil
}

func enrollSandbox(box sandboxView) error {
	s, err := connectSandbox(box)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.enroll(); err != nil {
		return err
	}
	if err := s.install(); err != nil {
		return fmt.Errorf("%s was enrolled, but its ssh profile was not installed: %w; retry `tinfoil sandbox enroll %s`", box.ID, err, box.ID)
	}
	return nil
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
	return readSandboxKeys(dir)
}

func readSandboxKeys(dir string) (*sandboxKeys, error) {
	credential, err := readOwnerCredential(filepath.Join(dir, sandboxDiskKeyName))
	if err != nil {
		return nil, fmt.Errorf("no disk key in %s; this sandbox requires its saved signing credential: %w", dir, err)
	}
	defer clear(credential.Key)
	keys := &sandboxKeys{dir: dir, sshKeyPath: filepath.Join(dir, sandboxSSHKeyName),
		diskKey: base64.StdEncoding.EncodeToString(credential.Key), ownerSeed: credential.SigningSeed}
	err = ensureOwnerSSHKey(keys.sshKeyPath, credential.SigningSeed)
	if err != nil {
		return nil, fmt.Errorf("missing or invalid sandbox login key in %s: %w", dir, err)
	}
	keys.agentKey, err = loadSSHKey(filepath.Join(dir, sandboxAgentKeyName))
	return keys, err
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
	if box.State == sandboxStateRunning || box.State == sandboxStateStopped {
		if box.State == sandboxStateStopped {
			fmt.Printf("Start:    tinfoil sandbox start %s\n", box.ID)
		}
		fmt.Printf("Connect:  ssh %s\n", box.ID)
	}
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

// Native ssh reads an OpenSSH encoding of the same key committed at measured boot.
// Existing files must match; a different login identity is never silently adopted.
func ensureOwnerSSHKey(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return errors.New("invalid owner key seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	saved, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return err
		}
		saved = pem.EncodeToMemory(block)
		defer clear(saved)
		return writeNewFile(path, saved)
	}
	if err != nil {
		return err
	}
	defer clear(saved)
	signer, err := ssh.ParsePrivateKey(saved)
	if err != nil {
		return err
	}
	key, _ := ssh.NewPublicKey(private.Public())
	if !bytes.Equal(signer.PublicKey().Marshal(), key.Marshal()) {
		return errors.New("saved SSH identity does not match the measured owner key")
	}
	return nil
}
