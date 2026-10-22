package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSandboxRepo   = "tinfoilsh/confidential-agent-sandbox"
	sandboxLoginUser     = "sandbox"
	sandboxOwnerEnv      = "SANDBOX_OWNER_PUBLIC_KEY"
	sandboxDiskKeyName   = "disk.key"
	sandboxSSHKeyName    = "owner_ed25519"
	sandboxBootTimeout   = 10 * time.Minute
	sandboxEnrollTimeout = 2 * time.Minute
	maxEnrollReplyBytes  = 1 << 12

	// Controlplane gives a new sandbox this workspace size when none is chosen.
	defaultWorkspaceSizeGB = 16
)

// sandboxWorkspaceSizesGB are the workspace volume sizes Controlplane accepts,
// in decimal gigabytes.
var sandboxWorkspaceSizesGB = []int{2, 4, 8, 16, 32, 64}

// workspaceSizeChoices lists the allowed workspace sizes as "2, 4, ..., or
// 64", with unit after each size.
func workspaceSizeChoices(unit string) string {
	sizes := make([]string, len(sandboxWorkspaceSizesGB))
	for i, size := range sandboxWorkspaceSizesGB {
		sizes[i] = strconv.Itoa(size) + unit
	}
	last := len(sizes) - 1
	return strings.Join(sizes[:last], ", ") + ", or " + sizes[last]
}

// Restrict names used by older credential directories to one path component.
var sandboxNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

type sandboxKeys struct {
	dir             string
	diskKey         []byte
	sshKeyPath      string
	agentKey        string
	monitorIdentity string
}

var sandboxYes bool

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.AddCommand(sandboxStatusCmd, sandboxStartCmd, sandboxRestartCmd, sandboxStopCmd, sandboxDeleteCmd, sandboxEnrollCmd)
	for _, cmd := range []*cobra.Command{sandboxStartCmd, sandboxRestartCmd, sandboxEnrollCmd} {
		addTrustDangerousFlag(cmd)
	}
	sandboxDeleteCmd.Flags().BoolVar(&sandboxYes, "yes", false, "Skip the confirmation prompt")
	for _, cmd := range []*cobra.Command{sandboxStartCmd, sandboxRestartCmd} {
		cmd.Flags().Bool("no-enroll", false, "Boot without unlocking or enrolling this machine's keys")
	}
	silenceUsageRecursive(sandboxCmd)
}

var sandboxCmd = &cobra.Command{
	Use: "sandbox", Aliases: []string{"sandboxes"}, Short: "Manage your confidential sandboxes", SilenceUsage: true,
}

var sandboxStatusCmd = newManagedStatusCmd("sandbox")

var sandboxStartCmd = &cobra.Command{
	Use: "start [id|name]", Short: "Start a stopped sandbox and enroll this machine's keys into it",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("start"),
}
var sandboxRestartCmd = &cobra.Command{
	Use: "restart [id|name]", Short: "Restart a sandbox and enroll this machine's keys into it",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("restart"),
}
var sandboxStopCmd = &cobra.Command{
	Use: "stop [id|name]", Short: "Stop a sandbox, keeping its workspace",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("stop"),
}
var sandboxDeleteCmd = &cobra.Command{
	Use: "delete [id|name]", Short: "Delete a sandbox, keeping its workspace volume",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("delete"),
}
var sandboxEnrollCmd = &cobra.Command{
	Use: "enroll [id|name]", Short: "Attest, enroll and install the SSH profile for a running sandbox",
	Long: "Verify the current boot, unlock the workspace and install the SSH profile. Reuse the original encryption credentials and owner key; rerun after a lost reply or reboot.",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("enroll"),
}

func runSandboxAction(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		row, err := managedRow(client, "sandbox", args[0])
		if action == "delete" && missingContainer(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %s is already deleted. Saved encryption credentials are kept.\n", args[0])
			return nil
		}
		if err != nil {
			return err
		}
		switch action {
		case "delete":
			fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s keeps its encrypted workspace volume and storage charges until `tinfoil volume delete` removes it. Keep your saved encryption credentials.\n", row.Name)
			if err := confirmYes(sandboxYes, "sandbox delete"); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/containers/%s", row.ID), nil, nil, nil); err != nil && !missingContainer(err) {
				return err
			}
			if err := forgetSandbox(row.Name, row.ID); err != nil {
				return fmt.Errorf("%s is deleted, but %w", row.Name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Saved encryption credentials are kept. Remove any access grants in the Monitor UI.\n", row.Name)
			return nil
		case "stop":
			stopped, err := stopContainer(client, *row)
			if err != nil {
				return err
			}
			return renderContainer(stopped)
		case "start", "restart":
			started, err := startSandboxRow(client, *row, action == "restart")
			if err != nil {
				return err
			}
			row = &started
			if noEnroll, _ := cmd.Flags().GetBool("no-enroll"); noEnroll {
				return renderContainer(*row)
			}
			if row.Volumes == nil {
				row, err = resolveContainerDetail(client, row.ID)
				if err != nil {
					return err
				}
			}
		}
		target, err := resolveWorkload(*row, defaultSandboxRepo, repo)
		if err != nil {
			return err
		}
		s, err := connectSandbox(target)
		if err != nil {
			return err
		}
		defer s.close()
		if err := s.enroll(); err != nil {
			return err
		}
		if err := s.install(); err != nil {
			return fmt.Errorf("%s was enrolled, but its ssh profile was not installed: %w; retry `tinfoil sandbox enroll %s`", target.Name, err, target.Name)
		}
		return renderContainer(*row)
	}
}

func startSandboxRow(client *cpClient, row containerView, restart bool) (containerView, error) {
	if restart || row.Status == statusStopped || row.Status == statusFailed {
		if err := validateSandboxNetwork(row); err != nil {
			return row, err
		}
		var err error
		if restart {
			row, err = stopContainer(client, row)
			if err != nil {
				return row, err
			}
		}
		fmt.Fprintf(os.Stderr, "Booting %s. A cold boot takes a few minutes.\n", row.Name)
		row, err = postContainerAction(client, row.ID, "deploy", nil)
		if err != nil {
			return row, err
		}
	}
	if err := failureError(row); err != nil {
		return row, err
	}
	if row.Status != statusRunning {
		return followContainer(client, row.ID, row)
	}
	return row, nil
}

func sandboxNetworkPolicy(monitorID string) containerNetworkPolicy {
	return containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{
		ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22},
	}}}
}

// The fixed endpoint is usable only with an explicit matching alias policy.
func sandboxNetworkMatches(row containerView) bool {
	policy := row.NetworkPolicy
	if policy == nil || policy.Public || policy.EgressMode != "restricted" || len(policy.Egress) != 1 {
		return false
	}
	peer := policy.Egress[0]
	return looksLikeUUID(peer.ContainerID) && peer.Port == 22 && peer.Alias != nil &&
		*peer.Alias == (containerAlias{IP: "10.254.0.1", Port: 22})
}

func validateSandboxNetwork(row containerView) error {
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	if env["NO_MONITOR"] == "1" {
		if row.NetworkPolicy != nil {
			return errors.New("sandbox with NO_MONITOR=1 must have no network policy")
		}
		return nil
	}
	if !sandboxNetworkMatches(row) {
		return errors.New("sandbox requires a private TCP alias for its selected Monitor; update its network policy")
	}
	return nil
}

func sandboxName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !sandboxNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid sandbox name %q: use letters, digits, dashes or underscores, starting with a letter or digit, up to 63 characters", raw)
	}
	return name, nil
}

const (
	sandboxAgentKeyName    = "agent_ed25519"
	sandboxEnrolledKeyName = "enrolled_host_key"

	// Monitor routes to a sandbox boot by a name derived from its SSH host key.
	sandboxRouteSuffix = ".sandbox.invalid"
	// The device key authorizes routes; setup also requires the sandbox identity.
	monitorSSHUser           = "device"
	monitorSandboxUserPrefix = "device+sandbox:"
	monitorSandboxEnrollment = "sandbox-enrollment-v1"
	monitorJumpSuffix        = ".monitor"
)

// One command keeps one verified sandbox connection through enrollment and SSH setup.
type sandboxSession struct {
	box         containerView
	keys        *sandboxKeys
	expires     time.Time
	monitor     *ssh.Client
	profile     sshProfile
	signer      ssh.Signer
	signerClose func()
	monitorKey  string
	initialized bool
}

type sandboxReceipt struct {
	BootKey   string `json:"boot_key"`
	MonitorID string `json:"monitor_id,omitempty"`
}

type sandboxResource struct {
	ID, Instance, Owner string
	Volumes             map[string]string
}

func connectSandbox(target *workloadTarget) (_ *sandboxSession, err error) {
	row, env := target.containerView, target.env
	if err := requireRunningConnection("Sandbox", row); err != nil {
		return nil, err
	}
	if len(row.Volumes) != 1 || !looksLikeUUID(row.Volumes["workspace"]) {
		return nil, errors.New("sandbox has no unique workspace volume binding")
	}
	noMonitor := env["NO_MONITOR"] == "1"
	if !looksLikeUUID(env["SANDBOX_INSTANCE_ID"]) {
		return nil, errors.New("sandbox release lacks a measured instance ID; use compatible templates")
	}
	if err := validateSandboxNetwork(row); err != nil {
		return nil, err
	}
	if noMonitor && (row.SSHPort < 1 || row.SSHPort > maxConnectionPort) {
		return nil, errors.New("sandbox has no published SSH port")
	}
	scope, cp, err := currentScope()
	if err != nil {
		return nil, err
	}
	var monitor *workloadTarget
	if !noMonitor {
		fmt.Fprintln(os.Stderr, "Checking the selected Monitor for sandbox "+row.Name)
		peer, err := resolveContainerDetail(cp, row.NetworkPolicy.Egress[0].ContainerID)
		if err != nil {
			return nil, err
		}
		monitor, err = resolveWorkload(*peer, monitorRepo, "")
		if err != nil {
			return nil, fmt.Errorf("selected Monitor %s: %w; review its configuration with `tinfoil monitor open %s`", peer.Name, err, peer.Name)
		}
		if err := requireRunningConnection("Monitor", *peer); err != nil {
			return nil, err
		}
	}
	dir, err := credentialDir(scope, row)
	if err != nil {
		return nil, err
	}
	record := sandboxResource{row.ID, env["SANDBOX_INSTANCE_ID"], env[sandboxOwnerEnv], row.Volumes}
	raw, _ := json.Marshal(record)
	saved, readErr := os.ReadFile(filepath.Join(dir, "resource.json"))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if readErr == nil && !bytes.Equal(saved, raw) {
		return nil, errors.New("sandbox instance, owner or storage binding changed")
	}
	credential, err := sandboxWorkspaceCredential(scope, dir, record, readErr == nil)
	if err != nil {
		return nil, err
	}
	defer credential.clear()
	keys := &sandboxKeys{dir: dir, diskKey: bytes.Clone(credential.Key)}
	if !noMonitor {
		if readErr != nil {
			if _, err := ensureSSHKey(filepath.Join(dir, sandboxAgentKeyName)); err != nil {
				return nil, err
			}
		}
		keys.agentKey, err = loadSSHKey(filepath.Join(dir, sandboxAgentKeyName))
		if err != nil {
			return nil, err
		}
		identity, err := os.ReadFile(filepath.Join(dir, sandboxAgentKeyName))
		if err != nil {
			return nil, err
		}
		keys.monitorIdentity = string(identity)
	}
	if err := writeAtomic(filepath.Join(dir, "resource.json"), raw); err != nil {
		return nil, err
	}
	s := &sandboxSession{box: row, keys: keys}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.signer, keys.sshKeyPath, s.signerClose, err = ownerSigner(credential, dir)
	if err != nil {
		return nil, err
	}
	var receipt sandboxReceipt
	if err := readStorageJSON(filepath.Join(dir, sandboxEnrolledKeyName), &receipt); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.initialized = receipt.BootKey != ""
	if noMonitor {
		host, expires, err := attestConnection(nil, row.Domain, target.source, "")
		if err != nil {
			return nil, err
		}
		s.expires = expires
		s.profile = sshProfile{name: row.Name, hostName: row.Domain, port: row.SSHPort, hostKeyAlias: row.Domain,
			user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: host, resourceID: scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + row.ID}
		fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\nWarning: sandbox has NO_MONITOR=1; its network traffic is not being tunneled through Monitor.\n", row.Name)
		return s, nil
	}
	if err := s.configureMonitor(scope, monitor, receipt.MonitorID != monitor.ID); err != nil {
		return nil, err
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		waiting := false
		for {
			conn, err := s.monitor.DialContext(ctx, "tcp", net.JoinHostPort(bootstrapRoute("sandbox-v2:"+record.Instance), "443"))
			var channel *ssh.OpenChannelError
			if !errors.As(err, &channel) || channel.Reason != ssh.ConnectionFailed {
				if err == nil {
					fmt.Fprintf(os.Stderr, "Sandbox %s route connected through Monitor; requesting attestation.\n", row.Name)
				}
				return conn, err
			}
			if !waiting {
				fmt.Fprintf(os.Stderr, "Monitor has no available attestation route for sandbox %s; waiting for its reverse SSH connection.\n", row.Name)
				waiting = true
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("sandbox reverse SSH route through Monitor did not become available: %w", ctx.Err())
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	host, expires, err := attestConnection(dial, row.Domain, target.source, "")
	if err != nil {
		var denied *ssh.OpenChannelError
		if errors.As(err, &denied) && denied.Reason == ssh.Prohibited {
			return nil, fmt.Errorf("Monitor route access denied; restore this device with `tinfoil monitor open %s`, then retry", monitor.Name)
		}
		return nil, fmt.Errorf("sandbox attestation through Monitor: %w", err)
	}
	s.expires = expires
	fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\n", row.Name)
	s.profile = sshProfile{name: row.Name, hostName: routeName(host), port: defaultSSHPort, hostKeyAlias: row.Domain,
		user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: host, jump: s.profile.jump, resourceID: scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + row.ID}
	return s, nil
}

func (s *sandboxSession) close() {
	clear(s.keys.diskKey)
	if s.monitor != nil {
		s.monitor.Close()
	}
	if s.signerClose != nil {
		s.signerClose()
	}
}

func (s *sandboxSession) configureMonitor(scope accountScope, target *workloadTarget, enroll bool) error {
	dir, err := monitorRecord(scope, target)
	if err != nil {
		return err
	}
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return err
	}
	agentKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.keys.agentKey))
	if err != nil {
		return fmt.Errorf("sandbox agent key: %w", err)
	}
	connect := func() error {
		if profile.ConfigSource != target.source {
			return errors.New("Monitor configuration needs fresh attestation")
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(profile.HostKey))
		if err != nil {
			return err
		}
		device, err := loadSigner(filepath.Join(dir, monitorDeviceKeyName))
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Connecting to Monitor for sandbox "+s.box.Name)
		conn, err := net.DialTimeout("tcp", profile.Address, 30*time.Second)
		if err != nil {
			return err
		}
		s.monitor, err = connectOwnerSigner(conn, profile.Domain, key, device, monitorSandboxUserPrefix+ssh.FingerprintSHA256(agentKey))
		return err
	}
	connectErr := connect()
	// Monitors without the handshake check require owner enrollment on every setup.
	if connectErr != nil || !s.initialized || enroll || !slices.Contains(strings.Fields(string(s.monitor.ServerVersion())), monitorSandboxEnrollment) {
		if s.monitor != nil {
			s.monitor.Close()
		}
		owner, ownerDir, err := connectMonitorOwner(context.Background(), scope, target, false)
		if err != nil {
			return err
		}
		defer owner.Close()
		dir = ownerDir
		device, err := loadSSHKey(filepath.Join(dir, monitorDeviceKeyName))
		if err != nil {
			return fmt.Errorf("restore Monitor device key: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Registering sandbox "+s.box.Name+" and this device with Monitor")
		err = pairSandboxMonitor(owner, dir, s.box.Name, device, s.keys.agentKey)
		if err != nil {
			return err
		}
		if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
			return err
		}
		if err := connect(); err != nil {
			return err
		}
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(profile.HostKey))
	if err != nil {
		return err
	}
	ip, port, _ := net.SplitHostPort(profile.Address)
	portNumber, _ := strconv.Atoi(port)
	s.monitorKey = profile.HostKey
	s.profile.jump = monitorJump(s.box.Name, ip, portNumber, dir, key, profile.Domain)
	return nil
}

// monitorJump is the hop through the Monitor. It must present the device key:
// the Monitor gives its owner key (by default the user's ~/.ssh/id_ed25519)
// an owner-only session that cannot open routes to sandboxes, and that key is
// usually in ssh-agent. The device key is an unencrypted file, so the hop needs
// no agent.
func monitorJump(sandbox, host string, port int, dir string, hostKey ssh.PublicKey, domain string) *sshProfile {
	return &sshProfile{name: sandbox + monitorJumpSuffix, hostName: host, port: port, user: monitorSSHUser, identityFile: filepath.Join(dir, monitorDeviceKeyName), hostKey: hostKey, hostKeyAlias: domain, noAgent: true}
}

func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

func (s *sandboxSession) enroll() error {
	if !time.Now().Before(s.expires) {
		return errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	dial := func() (*ssh.Client, error) {
		if !time.Now().Before(s.expires) {
			return nil, errors.New("sandbox attestation expired; verify it again before unlocking")
		}
		ctx, cancel := context.WithTimeout(context.Background(), sandboxEnrollTimeout)
		defer cancel()
		address := net.JoinHostPort(s.profile.hostName, strconv.Itoa(s.profile.port))
		var conn net.Conn
		var err error
		if s.monitor == nil {
			conn, err = (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", address)
		} else {
			conn, err = s.monitor.DialContext(ctx, "tcp", address)
		}
		if err != nil {
			return nil, err
		}
		client, err := connectOwnerSigner(conn, s.box.Domain, s.profile.hostKey, s.signer, sandboxLoginUser)
		if err == nil && !time.Now().Before(s.expires) {
			client.Close()
			return nil, errors.New("sandbox attestation expired during SSH handshake")
		}
		return client, err
	}
	message := "Initializing sandbox " + s.box.Name + " encrypted workspace"
	if s.initialized {
		message = "Unlocking sandbox " + s.box.Name + " encrypted workspace"
	}
	fmt.Fprintln(os.Stderr, message)
	err := configureSandbox(dial, s.keys, s.monitorKey, !s.initialized)
	if err != nil {
		return fmt.Errorf("%w; retry with `tinfoil sandbox enroll %s`", err, s.box.Name)
	}
	receipt := sandboxReceipt{BootKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.profile.hostKey)))}
	if s.monitor != nil {
		receipt.MonitorID = s.box.NetworkPolicy.Egress[0].ContainerID
	}
	if err := writeStorageJSON(filepath.Join(s.keys.dir, sandboxEnrolledKeyName), receipt, false); err != nil {
		return err
	}
	s.initialized = true
	fmt.Fprintf(os.Stderr, "Prepared %s over SSH with the keys in %s\n", s.box.Name, s.keys.dir)
	return nil
}

func (s *sandboxSession) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return installSandboxAlias(s.profile, home)
}

// Preserve aliases owned by another identity.
func installSandboxAlias(p sshProfile, home string) error {
	if owned, err := ownsSSHProfile(home, p.name, p.resourceID); err != nil || !owned {
		return errors.Join(err, fmt.Errorf("~/.ssh/tinfoil/%s.conf is the profile of another resource; choose --name ALIAS or remove this profile", p.name))
	}
	return p.installTo(home, os.Stdin, os.Stderr, false, true)
}

func ownsSSHProfile(home, name, resource string) (bool, error) {
	existing, err := os.ReadFile(filepath.Join(home, ".ssh", "tinfoil", name+".conf"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return resource != "" && bytes.HasPrefix(existing, []byte("# tinfoil-resource: "+resource+"\n")), err
}

// Remove the local SSH profile while keeping the saved keys.
func forgetSandbox(name, id string) error {
	if id == "" {
		return nil
	}
	scope, _, err := currentScope()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	owned, err := ownsSSHProfile(home, name, scope.ControlplaneURL+"/"+scope.OrgID+"/"+scope.UserID+"/"+id)
	if err != nil || !owned {
		return err
	}
	for _, suffix := range []string{".conf", ".known_hosts"} {
		if err := os.Remove(filepath.Join(home, ".ssh", "tinfoil", name+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func loadSSHKey(path string) (string, error) {
	signer, err := loadSigner(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

const installSandboxMonitorCommand = `sudo -n sh -c '
set -eu
install -d -m 0750 -g sandbox /run/monitor
umask 077
cat > /run/monitor/identity
printf "monitor %s\n" "$1" > /run/monitor/known_hosts
chmod 0600 /run/monitor/identity /run/monitor/known_hosts
chown sandbox:sandbox /run/monitor/identity /run/monitor/known_hosts
if [ -d /run/systemd/system ]; then
    systemctl restart monitor-network.service
fi
' sh`

func configureSandbox(dial func() (*ssh.Client, error), keys *sandboxKeys, monitorKey string, initialize bool) error {
	if monitorKey != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(monitorKey))
		if err != nil {
			return fmt.Errorf("Monitor host key: %w", err)
		}
		if _, err := ssh.ParsePrivateKey([]byte(keys.monitorIdentity)); err != nil {
			return fmt.Errorf("Monitor agent identity: %w", err)
		}
		identity := []byte(keys.monitorIdentity)
		defer clear(identity)
		command := installSandboxMonitorCommand + " " + shellQuote(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
		if err := sendOwnerCommand(dial, command, identity); err != nil {
			return fmt.Errorf("install Monitor credentials: %w", err)
		}
	}
	command := "/usr/local/bin/workspace-unlock"
	if initialize {
		command += " --initialize"
	}
	// A previous request may have opened the disk before its SSH reply was lost.
	command = "if test -S /run/tinfoil/volumes/workspace/control.sock; then " + command +
		"; else findmnt -rn -M /mnt/disk -t ext4 -O rw >/dev/null; fi"
	if err := sendOwnerCommand(dial, command, keys.diskKey); err != nil {
		return fmt.Errorf("unlock workspace: %w", err)
	}
	return nil
}

func sendOwnerCommand(dial func() (*ssh.Client, error), command string, body []byte) error {
	client, err := dial()
	if err != nil {
		return err
	}
	defer client.Close()
	timer := time.AfterFunc(sandboxBootTimeout, func() { client.Close() })
	defer timer.Stop()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(body)
	var message limitedUnlockOutput
	session.Stderr = &message
	if err := session.Run(command); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(message)))
	}
	return nil
}

type limitedUnlockOutput []byte

func (b *limitedUnlockOutput) Write(p []byte) (int, error) {
	n := min(len(p), maxEnrollReplyBytes-len(*b))
	*b = append(*b, p[:n]...)
	return len(p), nil
}
