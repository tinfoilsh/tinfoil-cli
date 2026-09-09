package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	// Sandbox records omit their source repo, so the CLI uses the release
	// deployed by the orchestrator unless --repo overrides it.
	defaultSandboxRepo = "tinfoilsh/confidential-agent-sandbox"

	sandboxLoginUser = "sandbox"

	sandboxEnrollPath = "/enroll"

	sandboxStateRunning = "running"
	sandboxStateStopped = "stopped"
	sandboxStatePending = "pending"

	// The volume worker requires the same length as volumeKeyBytes in
	// confidential-agent-sandbox.
	sandboxDiskKeyBytes = 64

	// cvmimage's volume worker derives the same identity from the same key.
	sealKeyInfo = "tinfoil seal identity v1"

	sandboxDiskKeyName = "disk.key"
	sandboxSSHKeyName  = "id_ed25519"

	sandboxBootTimeout = 10 * time.Minute

	sandboxEnrollTimeout = 2 * time.Minute

	maxEnrollReplyBytes = 1 << 12
)

// The control plane uses the same pattern. It also prevents path traversal
// when the name becomes a key directory.
var sandboxNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

type sandboxView struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Permit    string `json:"permit,omitempty"`
}

type sandboxKeys struct {
	dir        string
	diskKey    string
	publicKey  string
	sshKeyPath string
}

var (
	sandboxYes      bool
	sandboxSSHStart bool
	sandboxSSHStop  bool
)

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	sandboxCmd.AddCommand(
		sandboxListCmd,
		sandboxCreateCmd,
		sandboxStartCmd,
		sandboxRestartCmd,
		sandboxStopCmd,
		sandboxDestroyCmd,
		sandboxAcceptCmd,
		sandboxSSHCmd,
	)
	sandboxDestroyCmd.Flags().BoolVar(&sandboxYes, "yes", false, "Skip the confirmation prompt")
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
		var list []sandboxView
		if _, err := client.do("GET", "/api/sandboxes", nil, nil, &list); err != nil {
			return err
		}
		return renderSandboxes(list)
	},
}

var sandboxCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a sandbox and enroll this machine's keys into it",
	Long: `Create a sandbox, wait for it to boot, then spend its permit.

The keys are made on first use and kept in ~/.tinfoil/sandboxes/<name>. Keep
the disk key: it is what the workspace is encrypted with, and without it the
workspace cannot be opened again.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return renderSandbox(bootSandbox("POST", "/api/sandboxes", name, map[string]string{"id": name}))
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
		return renderSandbox(bootSandbox("POST", pathf("/api/sandboxes/%s/start", name), name, nil))
	},
}

var sandboxRestartCmd = &cobra.Command{
	Use:   "restart [name]",
	Short: "Restart a sandbox and enroll this machine's keys into it",
	Long: `Restart a sandbox, which is also how to recover one whose boot nobody
enrolled: the new boot mints a new nonce and a permit to go with it.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return renderSandbox(bootSandbox("POST", pathf("/api/sandboxes/%s/restart", name), name, nil))
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

var sandboxDestroyCmd = &cobra.Command{
	Use:     "destroy [name]",
	Aliases: []string{"delete", "rm"},
	Short:   "Destroy a sandbox and erase its workspace",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Destroying %s erases the encrypted disk behind this workspace.\n", name)
		fmt.Fprintln(os.Stderr, "Everything on it is lost for good and the name becomes free to reuse.")
		fmt.Fprintln(os.Stderr)
		if err := confirmYes(sandboxYes, "destroying a sandbox"); err != nil {
			return err
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/sandboxes/%s", name), nil, nil, nil); err != nil {
			return err
		}
		dir, err := sandboxKeyDir(name)
		if err != nil {
			return err
		}
		fmt.Printf("Destroyed %s. The keys in %s open nothing now and can be deleted.\n", name, dir)
		return nil
	},
}

var sandboxAcceptCmd = &cobra.Command{
	Use:   "accept [name]",
	Short: "Enroll this machine's keys into a sandbox with a permit",
	Long: `Spend a permit that was minted somewhere else, such as by the dashboard.

Paste the permit when prompted, or pipe it in. A permit is good for five
minutes, for one enrollment, and only for the boot it names, so a sandbox that
has been restarted since needs the permit from that restart.

The keys the enrollment names are made on first use and kept in
~/.tinfoil/sandboxes/<name>: the SSH key the sandbox seals its sshd to, and the
disk key its workspace is encrypted with. The disk key is written where the
dashboard's snippet writes it, so a sandbox claimed either way keeps working.

A permit is only spent by an enrollment that succeeds. The sandbox opens the
workspace before it claims one, so a disk key it refuses can be corrected and
the same permit used again.`,
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
		permit, err := promptSecret("permit", fmt.Sprintf("Paste the permit for %s: ", name))
		if err != nil {
			return err
		}
		return enrollSandbox(*box, permit)
	},
}

var sandboxSSHCmd = &cobra.Command{
	Use:   "ssh [name] [-- ssh arguments...]",
	Short: "SSH into a sandbox with its enrolled key",
	Long: `Open a shell in a sandbox over its attested TLS connection.

This is ` + "`tinfoil ssh`" + ` pointed at the sandbox's domain with the key
enrolled into it, so it works only after an enrollment on the current boot.
Anything after -- is handed to ssh unchanged.

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
			return fmt.Errorf("no SSH key for %s in %s: enroll one with `tinfoil sandbox accept %s`", name, dir, name)
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
	},
}

func bootSandbox(method, path, name string, body any) (*sandboxView, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	client.http.Timeout = sandboxBootTimeout

	fmt.Fprintf(os.Stderr, "Booting %s. A cold boot takes a few minutes.\n", name)
	var box sandboxView
	if _, err := client.do(method, path, nil, body, &box); err != nil {
		return nil, err
	}
	if box.Permit == "" {
		return nil, fmt.Errorf("%s reported no permit, so nothing can enroll into this boot; restart it with `tinfoil sandbox restart %s`", name, name)
	}
	if err := enrollSandbox(box, box.Permit); err != nil {
		return nil, fmt.Errorf("%s booted but no key was enrolled into it: %w", name, err)
	}
	return &box, nil
}

func stopSandbox(name string) (*sandboxView, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	var box sandboxView
	if _, err := client.do("POST", pathf("/api/sandboxes/%s/stop", name), nil, nil, &box); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Stopped %s. It gave up its compute; its workspace and domain stay.\n", name)
	return &box, nil
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
		return bootSandbox("POST", pathf("/api/sandboxes/%s/start", name), name, nil)
	case sandboxStatePending:
		return nil, fmt.Errorf("sandbox %s is still booting; wait for the start that is booting it to finish, or restart it with `tinfoil sandbox restart %s` if none is", name, name)
	default:
		return nil, fmt.Errorf("sandbox %s is %s; recover it with `tinfoil sandbox restart %s`", name, box.State, name)
	}
}

func enrollSandbox(box sandboxView, permit string) error {
	if strings.TrimSpace(permit) == "" {
		return errors.New("no permit given")
	}
	if box.State != sandboxStateRunning {
		return fmt.Errorf("sandbox %s is %s, so it has no boot to enroll into; start it first", box.ID, box.State)
	}
	if box.Domain == "" {
		return fmt.Errorf("sandbox %s reported no domain, so there is nothing to enroll into", box.ID)
	}
	keys, err := ensureSandboxKeys(box.ID)
	if err != nil {
		return err
	}

	fingerprint, err := verifiedTLSFingerprint(box.Domain, sandboxRepo(), "")
	if err != nil {
		if errors.Is(err, attestation.ErrRtmr3Mismatch) {
			return fmt.Errorf("sandbox %s is already sealed to an owner on this boot, so there is nothing left to enroll; restart it with `tinfoil sandbox restart %s`", box.ID, box.ID)
		}
		return fmt.Errorf("refusing to send the workspace key to an unverified sandbox: %w", err)
	}
	httpClient := &http.Client{
		Transport: &client.TLSBoundRoundTripper{ExpectedPublicKey: fingerprint},
		Timeout:   sandboxEnrollTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := postEnrollment(httpClient, "https://"+box.Domain+sandboxEnrollPath, permit, keys); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Enrolled %s with the keys in %s\n", box.ID, keys.dir)
	fmt.Fprintf(os.Stderr, "Connect with: tinfoil sandbox ssh %s\n", box.ID)
	return nil
}

// sandboxTunnelTarget is a tunnel into a sandbox that must be sealed to the
// disk key here, booting a stopped one only when --start asked for it. The key
// is read before anything starts: a boot that enrolls a freshly minted one
// cannot open the workspace that is already there.
func sandboxTunnelTarget(name string) (*tunnelTarget, error) {
	key, err := loadDiskKey(name)
	if err != nil {
		return nil, err
	}
	box, err := runningSandbox(name)
	if err != nil {
		return nil, err
	}
	return &tunnelTarget{name: name, host: box.Domain, repo: sandboxRepo(), sealedTo: sealFor(key)}, nil
}

// loadDiskKey never makes a key: a fresh one would fail the seal check against
// a workspace it did not open, with nothing to say why.
func loadDiskKey(name string) ([]byte, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, sandboxDiskKeyName)
	saved, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no disk key for %s in %s: enroll one with `tinfoil sandbox accept %s`", name, dir, name)
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

// sealFor is RTMR3 after the one extend a sandbox does per boot. The register
// starts at zero and an extend replaces it with the SHA-384 of its old value
// followed by the written digest, which cvmimage's volume worker takes over
// the public key it derives from the disk key that opened the workspace.
func sealFor(diskKey []byte) string {
	seed, _ := hkdf.Key(sha256.New, diskKey, nil, sealKeyInfo, ed25519.SeedSize)
	owner := sha512.Sum384(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	var zero [sha512.Size384]byte
	sealed := sha512.Sum384(append(zero[:], owner[:]...))
	return hex.EncodeToString(sealed[:])
}

func postEnrollment(httpClient *http.Client, url, permit string, keys *sandboxKeys) error {
	body, _ := json.Marshal(map[string]string{"key": keys.publicKey, "volume": keys.diskKey})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building enrollment: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+permit)

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
		return fmt.Errorf("the sandbox refused the enrollment (%s). A permit lasts five minutes and covers one boot, so restart the sandbox for a new one; if it was the workspace key that was refused, the key in %s is not the one this workspace was made with and the permit is still unspent",
			extractErrorMessage(answer), keys.dir)
	case http.StatusConflict:
		return errors.New("this boot already has an owner, so its permit is spent; restart the sandbox to enroll again")
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
	var box sandboxView
	if _, err := client.do("GET", pathf("/api/sandboxes/%s", name), nil, nil, &box); err != nil {
		return nil, err
	}
	return &box, nil
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
	return filepath.Join(filepath.Dir(config), "sandboxes", name), nil
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
	box.Permit = ""
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
	for i := range list {
		list[i].Permit = ""
	}
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
