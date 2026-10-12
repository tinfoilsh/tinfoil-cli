package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	sshKeyPath      string
	agentKey        string
	monitorIdentity string
}

var sandboxYes bool

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	sandboxCmd.AddCommand(sandboxListCmd, sandboxStartCmd, sandboxRestartCmd, sandboxStopCmd, sandboxDeleteCmd, sandboxEnrollCmd)
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
		fmt.Fprintf(os.Stderr, "Deleting %s frees its name. Its encrypted workspace volume stays, and is billed, until `tinfoil volume delete` removes it. Keep your saved encryption credentials.\n", name)
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
		if err := forgetSandbox(name, box.ContainerID); err != nil {
			return fmt.Errorf("%s is deleted, but %w", name, err)
		}
		fmt.Printf("Deleted %s. Saved encryption credentials are kept. Remove any access grants in the Monitor UI.\n", name)
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

New credentials are scoped by account and container UUID under ~/.tinfoil/resources.
A lost enrollment reply can be retried
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
	client.http.Timeout = sandboxBootTimeout

	var row containerView
	if _, err := client.do(method, path, nil, body, &row); err != nil {
		return nil, err
	}
	row, err = waitWorkload(client, row, statusRunning, sandboxBootTimeout)
	if err != nil {
		return nil, err
	}
	row, err = prepareSandboxEndpoint(client, row)
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
	if row.Status != statusStopped && row.Status != "failed" {
		return bootSandbox("GET", pathf("/api/containers/%s", row.ID), name, nil)
	}
	return bootSandbox("POST", pathf("/api/containers/%s/deploy", row.ID), name, nil)
}

// Lifecycle commands alone refresh the host grant and unmeasured bootstrap locator.
func prepareSandboxEndpoint(client *cpClient, row containerView) (containerView, error) {
	for attempt := 0; attempt < 3; attempt++ {
		endpoint, err := sandboxPeer(client, row)
		if err != nil {
			return row, fmt.Errorf("sandbox route unavailable; explicitly restart %s to refresh its host grant: %w", row.Name, err)
		}
		locator := net.JoinHostPort(endpoint.IP, strconv.Itoa(endpoint.Port))
		var variables map[string]string
		if len(row.Variables) != 0 {
			if err := json.Unmarshal(row.Variables, &variables); err != nil {
				return row, err
			}
		}
		if variables["MONITOR_ENDPOINT"] == locator {
			return row, nil
		}
		if _, err := client.do("POST", pathf("/api/containers/%s/stop", row.ID), nil, nil, &row); err != nil {
			return row, err
		}
		row, err = waitWorkload(client, row, statusStopped, sandboxBootTimeout)
		if err != nil {
			return row, err
		}
		if _, err := client.do("POST", pathf("/api/containers/%s/deploy", row.ID), nil, map[string]any{"variables": map[string]string{"MONITOR_ENDPOINT": locator}}, &row); err != nil {
			return row, err
		}
		row, err = waitWorkload(client, row, statusRunning, sandboxBootTimeout)
		if err != nil {
			return row, err
		}
	}
	return row, errors.New("Monitor endpoint kept changing; retry sandbox restart once it is stable")
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
