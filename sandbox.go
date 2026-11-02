package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	ehbp "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSandboxRepo  = "tinfoilsh/confidential-agent-sandbox"
	sandboxLoginUser    = "sandbox"
	sandboxOwnerEnv     = "SANDBOX_OWNER_PUBLIC_KEY"
	tmkOwnerKeyName     = "owner_tmk_ed25519"
	sandboxBootTimeout  = 10 * time.Minute
	maxEnrollReplyBytes = 1 << 12

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

var sandboxYes bool

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.AddCommand(sandboxStatusCmd, sandboxStartCmd, sandboxRestartCmd, sandboxStopCmd, sandboxDeleteCmd, sandboxEnrollCmd)
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
	Long: "Verify the current boot against the trusted sandbox and Monitor profiles, enroll or re-link it, unlock the workspace and install the SSH profile. Reuses the resource's saved keys; rerun after a lost reply, reboot or Monitor restart.",
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
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Remove any access grants in the Monitor UI.\n", row.Name)
			scope, _, err := currentScope()
			if err == nil {
				err = forgetDeletedResource(cmd.Context(), client, scope, *row)
			}
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Its keys are kept: %v\n", err)
			}
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
		target, err := managedWorkload(*row, defaultSandboxRepo)
		if err != nil {
			return err
		}
		s, err := connectSandbox(cmd.Context(), target)
		if err != nil {
			return err
		}
		defer s.close()
		if err := s.enroll(cmd.Context()); err != nil {
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

const (
	sandboxOwnerProtocol = "sandbox-owner-v1"
	sandboxEHBPKeyID     = "sandbox-ehbp"
	// The relay hop and the owner request share this one-minute operation window.
	ownerOperationWindow = time.Minute
	ownerRetryAttempts   = 4
	maxOwnerReplyBytes   = 2 << 20

	// Monitor routes to a sandbox boot by a name derived from its SSH host key.
	sandboxRouteSuffix = ".sandbox.invalid"
	// The device key authorizes routes to enrolled sandboxes.
	monitorSSHUser    = "device"
	monitorJumpSuffix = ".monitor"
)

// One command keeps one verified sandbox connection through enrollment and SSH setup.
type sandboxSession struct {
	box       containerView
	keys      *resourceKeys
	binding   mkBinding
	expires   time.Time
	monitor   *monitorSession
	owner     *sandboxOwner
	profile   sshProfile
	noMonitor bool
}

func connectSandbox(ctx context.Context, target *workloadTarget) (_ *sandboxSession, err error) {
	scope, cp, err := currentScope()
	if err != nil {
		return nil, err
	}
	row := target.containerView
	binding, size, err := sandboxBinding(cp, scope, target)
	if err != nil {
		return nil, err
	}
	var monitor *monitorSession
	if target.env["NO_MONITOR"] != "1" {
		fmt.Fprintln(os.Stderr, "Checking the selected Monitor for sandbox "+row.Name)
		peer, err := resolveContainerDetail(cp, row.NetworkPolicy.Egress[0].ContainerID)
		if err != nil {
			return nil, err
		}
		selected, err := managedWorkload(*peer, monitorRepo)
		if err != nil {
			return nil, fmt.Errorf("selected Monitor %s: %w", peer.Name, err)
		}
		if peer.OwnerKeyMode == "umk" && row.OwnerKeyMode == "tmk" {
			return nil, fmt.Errorf("a UMK Monitor cannot serve the synced sandbox %s", row.Name)
		}
		if monitor, err = connectMonitorOwner(ctx, scope, cp, selected, true); err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				monitor.close()
			}
		}()
	}
	dir, err := resourceDir(scope, row.ID, row.Name)
	if err != nil {
		return nil, err
	}
	keys, err := resolveResourceKeys(ctx, cp, scope, row, "sandbox", binding, dir, true)
	if err != nil {
		return nil, err
	}
	return openSandbox(ctx, scope, cp, target, binding, size, monitor, keys, dir)
}

// sandboxBinding checks a sandbox record from fresh inventory and returns its exact
// account, container, instance and workspace-volume binding and the bound volume's
// rendered size, which the trusted profile substitutes.
func sandboxBinding(cp *cpClient, scope accountScope, target *workloadTarget) (mkBinding, string, error) {
	row, env := target.containerView, target.env
	if err := requireRunningConnection("Sandbox", row); err != nil {
		return mkBinding{}, "", err
	}
	volumeID := row.Volumes["workspace"]
	if len(row.Volumes) != 1 || !validLowerUUID(volumeID) {
		return mkBinding{}, "", errors.New("sandbox has no unique workspace volume binding")
	}
	instance := env["SANDBOX_INSTANCE_ID"]
	if !validLowerUUID(instance) {
		return mkBinding{}, "", errors.New("sandbox release lacks a measured instance ID; use compatible templates")
	}
	if err := validateSandboxNetwork(row); err != nil {
		return mkBinding{}, "", err
	}
	if env["NO_MONITOR"] == "1" && (row.SSHPort < 1 || row.SSHPort > maxConnectionPort) {
		return mkBinding{}, "", errors.New("sandbox has no published SSH port")
	}
	list, err := listVolumes(cp)
	if err != nil {
		return mkBinding{}, "", fmt.Errorf("reading workspace volume %s: %w", volumeID, err)
	}
	i := slices.IndexFunc(list.Volumes, func(v volumeView) bool {
		return v.ID == volumeID && v.ContainerID == row.ID && v.Slot == "workspace" && v.Sandbox && v.SizeBytes > 0
	})
	if i < 0 {
		return mkBinding{}, "", fmt.Errorf("workspace volume %s is not attached to %s", volumeID, row.Name)
	}
	binding := mkBinding{Account: scope.account(), ContainerID: row.ID, InstanceID: &instance, VolumeID: &volumeID}
	return binding, formatVolumeSize(list.Volumes[i].SizeBytes), nil
}

// openSandbox verifies a sandbox under its trusted profile with resolved keys, directly
// for NO_MONITOR=1 or through the unlocked monitor's relay, and builds its SSH profile.
func openSandbox(ctx context.Context, scope accountScope, cp *cpClient, target *workloadTarget, binding mkBinding, size string,
	monitor *monitorSession, keys *resourceKeys, dir string) (_ *sandboxSession, err error) {
	row := target.containerView
	noMonitor := monitor == nil
	s := &sandboxSession{box: row, noMonitor: noMonitor, binding: binding, keys: keys, monitor: monitor}
	defer func() {
		if err != nil {
			keys.close()
		}
	}()
	identity := keys.identity
	if keys.mode == "tmk" {
		if identity, err = exportTMKIdentity(cp.login, dir, keys.ownerSeed); err != nil {
			return nil, err
		}
	}
	resourceID := scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + row.ID
	policy := sandboxPolicy(row.OwnerPublicKey, *binding.InstanceID, size, noMonitor)
	if noMonitor {
		stop := startConnectionProgress(os.Stderr, "Verifying sandbox attestation and SSH host key for "+row.Domain)
		verified, err := verifyWorkload(ctx, row.Domain, policy)
		stop()
		if err != nil {
			return nil, err
		}
		host, err := endorsedHostKey(row.Domain, verified)
		if err != nil {
			return nil, err
		}
		s.expires = verified.FreshnessExpiresAt
		s.profile = sshProfile{name: row.Name, hostName: row.Domain, port: row.SSHPort, hostKeyAlias: row.Domain,
			user: sandboxLoginUser, identityFile: identity, hostKey: host, resourceID: resourceID}
		fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\nWarning: sandbox has NO_MONITOR=1; its network traffic is not being tunneled through Monitor.\n", row.Name)
		return s, nil
	}
	s.owner = &sandboxOwner{request: monitor.request, instance: *binding.InstanceID, signer: keys.signer, owner: row.OwnerPublicKey}
	stop := startConnectionProgress(os.Stderr, "Requesting sandbox attestation through Monitor's relay")
	verified, err := s.owner.attest(ctx, policy)
	stop()
	if err != nil {
		return nil, fmt.Errorf("sandbox attestation through Monitor: %w", err)
	}
	host, err := endorsedHostKey(row.Domain, verified)
	if err != nil {
		return nil, err
	}
	s.expires = verified.FreshnessExpiresAt
	fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\n", row.Name)
	address, port, _ := net.SplitHostPort(monitor.address)
	portNumber, _ := strconv.Atoi(port)
	s.profile = sshProfile{name: row.Name, hostName: routeName(host), port: defaultSSHPort, hostKeyAlias: row.Domain,
		user: sandboxLoginUser, identityFile: identity, hostKey: host, resourceID: resourceID,
		jump: monitorJump(row.Name, address, portNumber, monitor.dir, monitor.hostKey, monitor.domain)}
	return s, nil
}

// relinkSandboxes points this freshly opened Monitor's sandboxes at its new verified host
// key after a Monitor-only restart. It re-enrolls a stale pin with each sandbox's active
// identity through its attested owner API and re-pins installed SSH profiles; it never
// restores an identity or initializes storage. Sandboxes this machine has no keys for,
// and identities Monitor no longer authorizes, are skipped.
func relinkSandboxes(ctx context.Context, scope accountScope, cp *cpClient, m *monitorSession, monitorID string) []error {
	var rows []containerView
	if _, err := cp.doContext(ctx, "GET", "/api/containers", nil, nil, nil, &rows); err != nil {
		return []error{fmt.Errorf("listing sandboxes to re-link: %w", err)}
	}
	var failures []error
	for _, listed := range rows {
		if listed.Repo != defaultSandboxRepo || listed.Debug || listed.Status != statusRunning || listed.ClerkUserID != scope.UserID ||
			!sandboxNetworkMatches(listed) || listed.NetworkPolicy.Egress[0].ContainerID != monitorID {
			continue
		}
		if err := relinkSandbox(ctx, scope, cp, m, monitorID, listed.ID); err != nil && !errors.Is(err, errNoLocalKeys) {
			failures = append(failures, fmt.Errorf("sandbox %s: %w", listed.Name, err))
		}
	}
	return failures
}

func relinkSandbox(ctx context.Context, scope accountScope, cp *cpClient, m *monitorSession, monitorID, id string) error {
	row, err := resolveContainerDetail(cp, id)
	if err != nil {
		return err
	}
	if row.ID != id || row.ClerkUserID != scope.UserID || row.Status != statusRunning || !sandboxNetworkMatches(*row) || row.NetworkPolicy.Egress[0].ContainerID != monitorID {
		return errors.New("its inventory changed while re-linking")
	}
	if m.keys.mode == "umk" && row.OwnerKeyMode == "tmk" {
		return fmt.Errorf("a UMK Monitor cannot serve the synced sandbox %s", row.Name)
	}
	target, err := managedWorkload(*row, defaultSandboxRepo)
	if err != nil {
		return err
	}
	binding, size, err := sandboxBinding(cp, scope, target)
	if err != nil {
		return err
	}
	dir, err := resourceDir(scope, row.ID, row.Name)
	if err != nil {
		return err
	}
	keys, err := resolveResourceKeys(ctx, cp, scope, *row, "sandbox", binding, dir, false)
	if err != nil {
		return err
	}
	if !m.authorizes(monitorIdentity(keys.monitorIdentitySeed)) {
		keys.close()
		return nil
	}
	s, err := openSandbox(ctx, scope, cp, target, binding, size, m, keys, dir)
	if err != nil {
		return err
	}
	defer keys.close()
	status, err := s.status(ctx)
	if err != nil {
		return err
	}
	if status.MonitorIdentity == nil || *status.MonitorIdentity != monitorIdentity(keys.monitorIdentitySeed) {
		return fmt.Errorf("its saved Monitor identity is not active; run `tinfoil sandbox enroll %s`", row.Name)
	}
	if host := authorizedKeyLine(m.hostKey); status.MonitorHostKey == nil || *status.MonitorHostKey != host {
		fmt.Fprintln(os.Stderr, "Re-linking sandbox "+row.Name+" to the current Monitor boot")
		if err := s.enrollSandbox(ctx, status.Volume, host); err != nil {
			return err
		}
	}
	return s.repinInstalled()
}

func (s *sandboxSession) close() {
	if s.keys != nil {
		s.keys.close()
	}
	if s.monitor != nil {
		s.monitor.close()
	}
}

// monitorJump is the hop through the Monitor. It must present the device key:
// the Monitor gives its owner key (by default the user's ~/.ssh/id_ed25519)
// an owner-only session that cannot open routes to sandboxes, and that key is
// usually in ssh-agent. The device key is an unencrypted file, so the hop needs
// no agent.
func monitorJump(sandbox, host string, port int, dir string, hostKey ssh.PublicKey, domain string) *sshProfile {
	return &sshProfile{name: sandbox + monitorJumpSuffix, hostName: host, port: port, user: monitorSSHUser, identityFile: filepath.Join(dir, monitorDeviceKeyName), hostKey: hostKey, hostKeyAlias: domain, noAgent: true}
}

type sandboxStatus struct {
	Protocol        string  `json:"protocol"`
	InstanceID      string  `json:"instance_id"`
	Volume          string  `json:"volume"`
	MonitorIdentity *string `json:"monitor_identity"`
	MonitorHostKey  *string `json:"monitor_host_key"`
}

// enroll decides from the actual Monitor identities and the sandbox's authenticated
// status whether this is a first enrollment, a reboot, or a re-link to a new Monitor
// boot. A missing identity is never silently restored: Monitor refuses one its owner removed.
func (s *sandboxSession) enroll(ctx context.Context) error {
	if !time.Now().Before(s.expires) {
		return errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	if s.noMonitor {
		return s.unlockDirect()
	}
	name := s.box.Name
	status, err := s.status(ctx)
	if err != nil {
		return err
	}
	agent := ""
	if s.keys.monitorIdentitySeed != nil {
		agent = monitorIdentity(s.keys.monitorIdentitySeed)
	}
	host := authorizedKeyLine(s.monitor.hostKey)
	switch {
	case status.MonitorIdentity != nil && *status.MonitorIdentity != agent:
		return fmt.Errorf("sandbox %s holds a different Monitor identity than its saved keys", name)
	case status.MonitorIdentity == nil && (agent == "" || !s.monitor.authorizes(agent)):
		if s.keys.storageKey == nil {
			if err := s.keys.generateUMKKeys("sandbox", s.box.OwnerPublicKey, s.binding); err != nil {
				return err
			}
			agent = monitorIdentity(s.keys.monitorIdentitySeed)
		}
		fmt.Fprintln(os.Stderr, "Registering sandbox "+name+" with Monitor")
		// Monitor itself refuses an identity the owner removed earlier.
		if err := s.monitor.enrollAgent(ctx, "sandbox-"+name, agent); err != nil {
			return err
		}
		return s.enrollSandbox(ctx, status.Volume, host)
	case !s.monitor.authorizes(agent):
		return fmt.Errorf("Monitor no longer authorizes sandbox %s; restore its identity in the Monitor UI, then retry", name)
	case status.MonitorIdentity == nil || status.Volume != "unlocked":
		return s.enrollSandbox(ctx, status.Volume, host)
	case status.MonitorHostKey == nil || *status.MonitorHostKey != host:
		fmt.Fprintln(os.Stderr, "Re-linking sandbox "+name+" to the current Monitor boot")
		return s.enrollSandbox(ctx, status.Volume, host)
	}
	return nil
}

// status is the sandbox's own authenticated report of its volume, Monitor identity and Monitor pin.
func (s *sandboxSession) status(ctx context.Context) (sandboxStatus, error) {
	var status sandboxStatus
	if err := s.owner.call(ctx, http.MethodGet, "/status", nil, &status); err != nil {
		return status, err
	}
	if status.Protocol != sandboxOwnerProtocol || status.InstanceID != s.owner.instance {
		return status, errors.New("sandbox owner status names another protocol or instance")
	}
	return status, nil
}

// enrollSandbox sends the Monitor identity, verified Monitor host key and disk key to
// the attested sandbox only. The volume worker formats only blank storage and
// otherwise unlocks it.
func (s *sandboxSession) enrollSandbox(ctx context.Context, volume, host string) error {
	if volume != "unlocked" {
		fmt.Fprintln(os.Stderr, "Unlocking sandbox "+s.box.Name+" encrypted workspace")
	}
	input := struct {
		MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
		MonitorHostKey      string `json:"monitor_host_key"`
		DiskKey             b64u   `json:"disk_key"`
		AllowInitialize     bool   `json:"allow_initialize"`
	}{s.keys.monitorIdentitySeed, host, s.keys.storageKey, true}
	var status sandboxStatus
	if err := s.owner.call(ctx, http.MethodPost, "/enroll", input, &status); err != nil {
		return fmt.Errorf("%w; rerun `tinfoil sandbox enroll %s` to reconcile", err, s.box.Name)
	}
	if status.Volume != "unlocked" {
		return fmt.Errorf("sandbox %s workspace is still %s; rerun `tinfoil sandbox enroll %s`", s.box.Name, status.Volume, s.box.Name)
	}
	fmt.Fprintf(os.Stderr, "Prepared %s through its attested owner API.\n", s.box.Name)
	return nil
}

func monitorIdentity(seed []byte) string {
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, _ := ssh.NewPublicKey(private.Public())
	return authorizedKeyLine(public)
}

func authorizedKeyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// sandboxOwner sends signed sandbox-owner-v1 requests sealed to the attested
// sandbox-ehbp key. Monitor's relay carries them but never sees plaintext.
type sandboxOwner struct {
	// request is Monitor's owner API, which carries the relay.
	request  func(method, path string, input, out any) error
	instance string
	signer   ssh.Signer
	owner    string
	client   *http.Client
	expires  time.Time
	// skew is the sandbox's clock minus ours, learned when it refuses a request's time.
	skew time.Duration
}

type relayHeaders struct {
	EncapsulatedKey string `json:"Ehbp-Encapsulated-Key"`
	ContentType     string `json:"Content-Type"`
}

type relayReply struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func (o *sandboxOwner) relay(target string, nonce *string, headers *relayHeaders, body []byte) (*relayReply, []byte, error) {
	input := struct {
		InstanceID string        `json:"instance_id"`
		Target     string        `json:"target"`
		Nonce      *string       `json:"nonce"`
		Headers    *relayHeaders `json:"headers"`
		Body       string        `json:"body"`
	}{o.instance, target, nonce, headers, base64.RawURLEncoding.EncodeToString(body)}
	var reply relayReply
	if err := o.request(http.MethodPost, "/sandboxes/relay", input, &reply); err != nil {
		return nil, nil, err
	}
	data, err := decodeB64U(reply.Body, -1)
	return &reply, data, err
}

// verifySandboxEvidence verifies relayed sandbox attestation; tests without CVM
// hardware substitute it while keeping the trusted profile check.
var verifySandboxEvidence = verifyWorkloadDocument

// attest verifies fresh nonce-bound sandbox evidence under policy and binds the
// owner channel to the endorsed sandbox-ehbp key of that same verification.
func (o *sandboxOwner) attest(ctx context.Context, policy workloadPolicy) (*verify.Verification, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(nonce)
	reply, doc, err := o.relay("attestation", &encoded, nil, nil)
	if err != nil {
		return nil, err
	}
	if reply.Status != http.StatusOK {
		return nil, fmt.Errorf("sandbox attestation returned HTTP %d", reply.Status)
	}
	verified, err := verifySandboxEvidence(ctx, doc, nonce, policy)
	if err != nil {
		return nil, err
	}
	spki, ok := verified.CryptoMaterialData(sandboxEHBPKeyID, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("sandbox endorses no %q key", sandboxEHBPKeyID)
	}
	raw, err := sandboxEHBPKey(spki)
	if err != nil {
		return nil, err
	}
	key, err := identity.FromPublicKeyBytes(raw)
	if err != nil {
		return nil, err
	}
	transport, err := ehbp.NewTransportWithIdentity(key, ehbp.WithHTTPClient(&http.Client{Transport: o}))
	if err != nil {
		return nil, err
	}
	o.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	o.expires = verified.FreshnessExpiresAt
	return verified, nil
}

// RoundTrip carries one sealed request through Monitor's relay and never retries it:
// a repeated ciphertext would repeat its nonce. call re-signs instead.
func (o *sandboxOwner) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	reply, data, err := o.relay("owner", nil, &relayHeaders{r.Header.Get(protocol.EncapsulatedKeyHeader), r.Header.Get("Content-Type")}, body)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	for name, value := range reply.Headers {
		header.Set(name, value)
	}
	return &http.Response{StatusCode: reply.Status, Header: header, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Request: r}, nil
}

// call signs one owner operation. While its outcome is unknown, it retries the same
// content and original time with a fresh nonce inside the one-minute window; every
// sandbox effect is safe to repeat.
func (o *sandboxOwner) call(ctx context.Context, method, path string, input, out any) error {
	var body []byte
	if input != nil {
		var err error
		if body, err = json.Marshal(input); err != nil {
			return err
		}
		defer clear(body)
	}
	request := ownerRequest{Protocol: sandboxOwnerProtocol, Owner: o.owner, Resource: o.instance, Method: method, Path: path,
		Body: base64.RawURLEncoding.EncodeToString(body), Operation: randomB64U(16), IssuedAt: time.Now().Add(o.skew).UnixMilli()}
	started := time.Now()
	var lastErr error
	for range ownerRetryAttempts {
		if !time.Now().Before(o.expires) {
			return errors.Join(errors.New("sandbox attestation expired; verify it again"), lastErr)
		}
		if time.Since(started) > ownerOperationWindow || ctx.Err() != nil {
			break
		}
		request.Nonce = randomB64U(ownerNonceBytes)
		envelope, err := signOwnerRequest(o.signer, request)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sandbox/owner/rpc", bytes.NewReader(envelope))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := o.client.Do(req)
		var reply []byte
		if err == nil {
			reply, err = io.ReadAll(io.LimitReader(resp.Body, maxOwnerReplyBytes+1))
			resp.Body.Close()
		}
		if err != nil || len(reply) > maxOwnerReplyBytes {
			lastErr = errors.Join(err, errors.New("the sandbox reply was lost"))
			continue
		}
		var refused struct {
			Error string
			Now   *int64
		}
		if resp.StatusCode == http.StatusUnauthorized && json.Unmarshal(reply, &refused) == nil && refused.Now != nil &&
			(refused.Error == "request_time_in_future" || refused.Error == "request_expired") {
			o.skew, request.IssuedAt = time.Until(time.UnixMilli(*refused.Now)), *refused.Now
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("sandbox %s %s: %d %s", method, path, resp.StatusCode, extractErrorMessage(reply))
		}
		return json.Unmarshal(reply, out)
	}
	return fmt.Errorf("sandbox %s %s has an unknown outcome: %w", method, path, lastErr)
}

func (s *sandboxSession) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return installSandboxAlias(s.profile, home)
}

// repinInstalled rewrites this resource's already installed SSH profiles, under the names
// they were installed with, with the current verified pins. It installs no new profile.
func (s *sandboxSession) repinInstalled() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	installed, err := filepath.Glob(filepath.Join(home, ".ssh", "tinfoil", "*.conf"))
	if err != nil {
		return err
	}
	for _, path := range installed {
		name := strings.TrimSuffix(filepath.Base(path), ".conf")
		if owned, err := ownsSSHProfile(home, name, s.profile.resourceID); err != nil || !owned {
			continue
		}
		profile := s.profile
		profile.name = name
		if profile.jump != nil {
			jump := *profile.jump
			jump.name = name + monitorJumpSuffix
			profile.jump = &jump
		}
		if err := profile.installTo(home, os.Stdin, os.Stderr, false, false); err != nil {
			return err
		}
	}
	return nil
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

// unlockDirect is owned by the explicit NO_MONITOR=1 profile: the measured owner
// unlocks the workspace over attested SSH. It is never a fallback for Monitor enrollment.
func (s *sandboxSession) unlockDirect() error {
	dial := func() (*ssh.Client, error) {
		if !time.Now().Before(s.expires) {
			return nil, errors.New("sandbox attestation expired; verify it again before unlocking")
		}
		address := net.JoinHostPort(s.profile.hostName, strconv.Itoa(s.profile.port))
		conn, err := (&net.Dialer{Timeout: 30 * time.Second}).Dial("tcp", address)
		if err != nil {
			return nil, err
		}
		return connectOwnerSigner(conn, s.box.Domain, s.profile.hostKey, s.keys.signer, sandboxLoginUser)
	}
	volume, err := sendOwnerCommand(dial, "/usr/local/bin/workspace-unlock --status", nil)
	if err != nil {
		return fmt.Errorf("workspace status: %w", err)
	}
	switch volume {
	case "unlocked":
		return nil
	case "locked":
	default:
		return fmt.Errorf("unexpected workspace status %q", volume)
	}
	if s.keys.storageKey == nil {
		if err := s.keys.generateUMKKeys("sandbox", s.box.OwnerPublicKey, s.binding); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "Unlocking sandbox "+s.box.Name+" encrypted workspace")
	if _, err := sendOwnerCommand(dial, "/usr/local/bin/workspace-unlock --initialize", s.keys.storageKey); err != nil {
		return fmt.Errorf("unlock workspace: %w; retry with `tinfoil sandbox enroll %s`", err, s.box.Name)
	}
	return nil
}

func sendOwnerCommand(dial func() (*ssh.Client, error), command string, body []byte) (string, error) {
	client, err := dial()
	if err != nil {
		return "", err
	}
	defer client.Close()
	timer := time.AfterFunc(sandboxBootTimeout, func() { client.Close() })
	defer timer.Stop()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(body)
	var output, message limitedUnlockOutput
	session.Stdout, session.Stderr = &output, &message
	if err := session.Run(command); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(message)))
	}
	return strings.TrimSpace(string(output)), nil
}

type limitedUnlockOutput []byte

func (b *limitedUnlockOutput) Write(p []byte) (int, error) {
	n := min(len(p), maxEnrollReplyBytes-len(*b))
	*b = append(*b, p[:n]...)
	return len(p), nil
}
