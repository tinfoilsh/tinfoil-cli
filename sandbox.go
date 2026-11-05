package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSandboxRepo = "tinfoilsh/confidential-agent-sandbox"
	sandboxLoginUser   = "sandbox"
	sandboxOwnerEnv    = "SANDBOX_OWNER_PUBLIC_KEY"
	tmkOwnerKeyName    = "owner_tmk_ed25519"
	sandboxBootTimeout = 10 * time.Minute

	// Controlplane gives a new sandbox this workspace size when none is chosen.
	defaultWorkspaceSizeGB = 16
	// sandboxWorkspaceSlot is the volume mount that holds a sandbox's workspace.
	sandboxWorkspaceSlot = "workspace"
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

func newSandboxCommand(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions) *cobra.Command {
	sandboxCmd := &cobra.Command{
		Use: "sandbox", Aliases: []string{"sandboxes"}, Short: "Manage your confidential sandboxes",
	}
	sandboxCmd.AddCommand(newSandboxStatusCommand(outputOpts), newSandboxStartCommand(identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxRestartCommand(identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxStopCommand(identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxDeleteCommand(identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}))
	return sandboxCmd
}

func newSandboxStatusCommand(outputOpts *outputOptions) *cobra.Command {
	sandboxStatusCmd := newManagedStatusCmd(outputOpts, "sandbox")

	return sandboxStatusCmd
}

func newSandboxStartCommand(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxStartCmd := &cobra.Command{
		Use: "start [id|name]", Short: "Start a sandbox and enroll this machine's keys",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "start"),
	}
	addTrustDangerousFlag(trustOpts, sandboxStartCmd)
	sandboxStartCmd.Flags().Bool("no-enroll", false, "Boot without unlocking or enrolling this machine's keys")
	return sandboxStartCmd
}
func newSandboxRestartCommand(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxRestartCmd := &cobra.Command{
		Use: "restart [id|name]", Short: "Restart a sandbox and enroll this machine's keys",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "restart"),
	}
	addTrustDangerousFlag(trustOpts, sandboxRestartCmd)
	sandboxRestartCmd.Flags().Bool("no-enroll", false, "Boot without unlocking or enrolling this machine's keys")
	return sandboxRestartCmd
}
func newSandboxStopCommand(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxStopCmd := &cobra.Command{
		Use: "stop [id|name]", Short: "Stop a sandbox, keeping its workspace",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "stop"),
	}

	return sandboxStopCmd
}
func newSandboxDeleteCommand(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxDeleteCmd := &cobra.Command{
		Use: "delete [id|name]", Short: "Delete a sandbox and its workspace volume",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "delete"),
	}
	sandboxDeleteCmd.Flags().BoolVar(&sandboxActionOpts.sandboxYes, "yes", false, "Skip the confirmation prompt")
	return sandboxDeleteCmd
}

func runSandboxAction(identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions, action string) func(*cobra.Command, []string) error {
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
			workspace := row.Volumes[sandboxWorkspaceSlot]
			deleted := row.Name
			if workspace == "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s. It has no attached workspace volume.\n", row.Name)
			} else {
				deleted += " and its workspace"
				fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s permanently deletes its workspace volume and all of its data. To keep the workspace, stop the sandbox and run `tinfoil volume detach %s` before deleting it.\n", row.Name, workspace)
			}
			if err := confirmYes(commandStreams(cmd), sandboxActionOpts.sandboxYes, "sandbox delete"); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/containers/%s", row.ID), nil, nil, nil); err != nil && !missingContainer(err) {
				return err
			}
			if err := forgetSandbox(row.Name, row.ID); err != nil {
				return fmt.Errorf("%s is deleted, but %w", row.Name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Saved encryption credentials are kept. Remove any access grants in the Monitor UI.\n", deleted)
			return nil
		case "stop":
			stopped, err := stopContainer(client, *row)
			if err != nil {
				return err
			}
			return renderContainer(commandStreams(cmd), outputOpts, stopped)
		case "start", "restart":
			started, err := startSandboxRow(commandStreams(cmd), client, *row, action == "restart")
			if err != nil {
				return err
			}
			row = &started
			if noEnroll, _ := cmd.Flags().GetBool("no-enroll"); noEnroll {
				return renderContainer(commandStreams(cmd), outputOpts, *row)
			}
			if row.Volumes == nil {
				row, err = resolveContainerDetail(client, row.ID)
				if err != nil {
					return err
				}
			}
		}
		target, err := resolveWorkload(commandStreams(cmd), rootOpts, trustOpts, *row, defaultSandboxRepo, rootOpts.repo)
		if err != nil {
			return err
		}
		s, err := connectSandbox(commandStreams(cmd), identityOpts, rootOpts, trustOpts, cmd.Context(), target)
		if err != nil {
			return err
		}
		defer s.close()
		if err := s.enroll(commandStreams(cmd), cmd.Context()); err != nil {
			return err
		}
		if err := s.install(commandStreams(cmd)); err != nil {
			return fmt.Errorf("%s was enrolled, but its ssh profile was not installed: %w; retry `tinfoil sandbox start %s`", target.Name, err, target.Name)
		}
		return renderContainer(commandStreams(cmd), outputOpts, *row)
	}
}

func startSandboxRow(streams commandIO, client *cpClient, row containerView, restart bool) (containerView, error) {
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
		fmt.Fprintf(streams.err, "Booting %s. A cold boot takes a few minutes.\n", row.Name)
		row, err = postContainerAction(client, row.ID, "deploy", nil)
		if err != nil {
			return row, err
		}
	}
	if err := failureError(row); err != nil {
		return row, err
	}
	if row.Status != statusRunning {
		return followContainer(streams, client, row.ID, row)
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
	sandboxOwnerRequest  = "sudo -n -- curl -sS --fail-with-body --unix-socket /run/workspace/owner.sock http://sandbox"
	sandboxStatusCommand = sandboxOwnerRequest + "/status"
	sandboxEnrollCommand = sandboxOwnerRequest + "/enroll --data-binary @-"
	ownerConnectTimeout  = owner.ConnectTimeout

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

func connectSandbox(streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, ctx context.Context, target *workloadTarget) (_ *sandboxSession, err error) {
	scope, cp, err := currentScope()
	if err != nil {
		return nil, err
	}
	row := target.containerView
	binding, err := sandboxBinding(scope, target)
	if err != nil {
		return nil, err
	}
	var monitor *monitorSession
	defer func() {
		if err != nil && monitor != nil {
			monitor.close()
		}
	}()
	if target.env["NO_MONITOR"] != "1" {
		fmt.Fprintln(streams.err, "Checking the selected Monitor for sandbox "+row.Name)
		peer, err := resolveContainerDetail(cp, row.NetworkPolicy.Egress[0].ContainerID)
		if err != nil {
			return nil, fmt.Errorf("sandbox %s's Monitor: %w", row.Name, err)
		}
		selected, err := resolveWorkload(streams, rootOpts, trustOpts, *peer, monitorRepo, "")
		if err != nil {
			return nil, fmt.Errorf("selected Monitor %s: %w; review its configuration with `tinfoil monitor open %s`", peer.Name, err, peer.Name)
		}
		if peer.OwnerKeyMode == "umk" && row.OwnerKeyMode == "tmk" {
			return nil, fmt.Errorf("a UMK Monitor cannot serve the synced sandbox %s", row.Name)
		}
		if monitor, err = connectMonitorOwner(streams, identityOpts, rootOpts, ctx, scope, cp, selected, true); err != nil {
			return nil, err
		}
	}
	dir, err := resourceDir(scope, row.ID, row.Name)
	if err != nil {
		return nil, err
	}
	keys, err := resolveResourceKeys(identityOpts, ctx, cp, scope, row, "sandbox", binding, dir, true)
	if err != nil {
		return nil, err
	}
	return openSandbox(streams, rootOpts, scope, cp, target, binding, monitor, keys, dir)
}

func sandboxBinding(scope accountScope, target *workloadTarget) (mkBinding, error) {
	row, env := target.containerView, target.env
	if err := requireRunningConnection("Sandbox", row); err != nil {
		return mkBinding{}, err
	}
	volumeID, instance := row.Volumes[sandboxWorkspaceSlot], env["SANDBOX_INSTANCE_ID"]
	if len(row.Volumes) != 1 || !validLowerUUID(volumeID) {
		return mkBinding{}, errors.New("sandbox has no unique workspace volume binding")
	}
	if !validLowerUUID(instance) {
		return mkBinding{}, errors.New("sandbox release lacks a measured instance ID; use compatible templates")
	}
	if env[sandboxOwnerEnv] != row.OwnerPublicKey {
		return mkBinding{}, errors.New("sandbox's measured owner is not its owner key")
	}
	if err := validateSandboxNetwork(row); err != nil {
		return mkBinding{}, err
	}
	if env["NO_MONITOR"] == "1" && (row.SSHPort < 1 || row.SSHPort > maxConnectionPort) {
		return mkBinding{}, errors.New("sandbox has no published SSH port")
	}
	return mkBinding{Account: scope.account(), ContainerID: row.ID, InstanceID: &instance, VolumeID: &volumeID}, nil
}

func openSandbox(streams commandIO, rootOpts *rootOptions, scope accountScope, cp *cpClient, target *workloadTarget, binding mkBinding, monitor *monitorSession, keys *resourceKeys, dir string) (_ *sandboxSession, err error) {
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
	if noMonitor {
		defer startConnectionProgress(streams.err, "Verifying sandbox attestation and SSH host key for "+row.Domain)()
		secure, err := newVerifiedClient(rootOpts, row.Domain, target.source, "")
		if err != nil {
			return nil, err
		}
		verified, err := secure.EnsureVerified(context.Background())
		if err != nil {
			return nil, fmt.Errorf("verifying %s: %w", row.Domain, err)
		}
		host, err := endorsedHostKey(row.Domain, verified)
		if err != nil {
			return nil, err
		}
		s.expires = verified.FreshnessExpiresAt()
		s.profile = sshProfile{name: row.Name, hostName: row.Domain, port: row.SSHPort, hostKeyAlias: row.Domain,
			user: sandboxLoginUser, identityFile: identity, hostKey: host, resourceID: resourceID}
		fmt.Fprintf(streams.err, "Sandbox %s attestation verified.\nWarning: sandbox has NO_MONITOR=1; its network traffic is not being tunneled through Monitor.\n", row.Name)
		return s, nil
	}
	s.owner = &sandboxOwner{request: monitor.request, instance: *binding.InstanceID, dial: s.dial, verifyEvidence: sandboxVerifier(rootOpts)}
	stop := startConnectionProgress(streams.err, "Requesting sandbox attestation through Monitor's relay")
	verified, err := s.owner.attest(target.source)
	stop()
	if err != nil {
		return nil, fmt.Errorf("sandbox attestation through Monitor: %w", err)
	}
	host, err := endorsedHostKey(row.Domain, verified)
	if err != nil {
		return nil, err
	}
	s.expires = verified.FreshnessExpiresAt()
	fmt.Fprintf(streams.err, "Sandbox %s attestation verified.\n", row.Name)
	address, port, _ := net.SplitHostPort(monitor.address)
	portNumber, _ := strconv.Atoi(port)
	s.profile = sshProfile{name: row.Name, hostName: routeName(host), port: defaultSSHPort, hostKeyAlias: row.Domain,
		user: sandboxLoginUser, identityFile: identity, hostKey: host, resourceID: resourceID,
		jump: monitorJump(row.Name, address, portNumber, monitor.dir, monitor.hostKey, monitor.domain)}
	return s, nil
}

func relinkSandboxes(streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, ctx context.Context, scope accountScope, cp *cpClient, m *monitorSession, monitorID string) []error {
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
		if err := relinkSandbox(streams, identityOpts, rootOpts, trustOpts, ctx, scope, cp, m, monitorID, listed.ID); err != nil && !errors.As(err, new(noLocalKeys)) {
			failures = append(failures, fmt.Errorf("sandbox %s: %w", listed.Name, err))
		}
	}
	return failures
}

func relinkSandbox(streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, ctx context.Context, scope accountScope, cp *cpClient, m *monitorSession, monitorID, id string) error {
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
	target, err := resolveWorkload(streams, rootOpts, trustOpts, *row, defaultSandboxRepo, "")
	if err != nil {
		return err
	}
	binding, err := sandboxBinding(scope, target)
	if err != nil {
		return err
	}
	dir, err := resourceDir(scope, row.ID, row.Name)
	if err != nil {
		return err
	}
	keys, err := resolveResourceKeys(identityOpts, ctx, cp, scope, *row, "sandbox", binding, dir, false)
	if err != nil {
		return err
	}
	if !m.authorizes(monitorIdentity(keys.monitorIdentitySeed)) {
		keys.close()
		return nil
	}
	s, err := openSandbox(streams, rootOpts, scope, cp, target, binding, m, keys, dir)
	if err != nil {
		return err
	}
	defer keys.close()
	status, err := s.status(ctx)
	if err != nil {
		return err
	}
	if status.MonitorIdentity == nil || *status.MonitorIdentity != monitorIdentity(keys.monitorIdentitySeed) {
		return fmt.Errorf("its saved Monitor identity is not active; run `tinfoil sandbox start %s`", row.Name)
	}
	if host := authorizedKeyLine(m.hostKey); status.MonitorHostKey == nil || *status.MonitorHostKey != host {
		fmt.Fprintln(streams.err, "Re-linking sandbox "+row.Name+" to the current Monitor boot")
		if err := s.enrollSandbox(streams, ctx, status.Volume, host); err != nil {
			return err
		}
	}
	return s.repinInstalled(streams)
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

func (s *sandboxSession) enroll(streams commandIO, ctx context.Context) error {
	if !time.Now().Before(s.expires) {
		return errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	if s.noMonitor {
		return s.unlockDirect(streams, ctx)
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
		fmt.Fprintln(streams.err, "Registering sandbox "+name+" with Monitor")
		if err := s.monitor.enrollAgent(streams, ctx, "sandbox-"+name, agent); err != nil {
			return err
		}
		return s.enrollSandbox(streams, ctx, status.Volume, host)
	case !s.monitor.authorizes(agent):
		return fmt.Errorf("Monitor no longer authorizes sandbox %s; restore its identity in the Monitor UI, then retry", name)
	case status.MonitorIdentity == nil || status.Volume != "unlocked":
		return s.enrollSandbox(streams, ctx, status.Volume, host)
	case status.MonitorHostKey == nil || *status.MonitorHostKey != host:
		fmt.Fprintln(streams.err, "Re-linking sandbox "+name+" to the current Monitor boot")
		return s.enrollSandbox(streams, ctx, status.Volume, host)
	}
	return nil
}

func (s *sandboxSession) status(ctx context.Context) (sandboxStatus, error) {
	var status sandboxStatus
	if err := s.owner.call(ctx, sandboxStatusCommand, nil, &status); err != nil {
		return status, err
	}
	if status.Protocol != sandboxOwnerProtocol || status.InstanceID != s.owner.instance {
		return status, errors.New("sandbox owner status names another protocol or instance")
	}
	return status, nil
}

func (s *sandboxSession) enrollSandbox(streams commandIO, ctx context.Context, volume, host string) error {
	if volume != "unlocked" {
		fmt.Fprintln(streams.err, "Unlocking sandbox "+s.box.Name+" encrypted workspace")
	}
	input := struct {
		MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
		MonitorHostKey      string `json:"monitor_host_key"`
		DiskKey             b64u   `json:"disk_key"`
		AllowInitialize     bool   `json:"allow_initialize"`
	}{s.keys.monitorIdentitySeed, host, s.keys.storageKey, true}
	var status sandboxStatus
	if err := s.owner.call(ctx, sandboxEnrollCommand, input, &status); err != nil {
		return fmt.Errorf("%w; rerun `tinfoil sandbox start %s` to reconcile", err, s.box.Name)
	}
	if status.Volume != "unlocked" {
		return fmt.Errorf("sandbox %s workspace is still %s; rerun `tinfoil sandbox start %s`", s.box.Name, status.Volume, s.box.Name)
	}
	fmt.Fprintf(streams.err, "Prepared %s over attested SSH.\n", s.box.Name)
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

type sandboxOwner struct {
	verifyEvidence sandboxEvidenceVerifier
	request        func(method, path string, input, out any) error
	instance       string
	dial           func(context.Context) (*ssh.Client, error)
	expires        time.Time
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func sandboxVerifier(rootOpts *rootOptions) sandboxEvidenceVerifier {
	if verify := rootOpts.dependencies.verifySandboxEvidence; verify != nil {
		return verify
	}
	return func(doc, nonce []byte, source string) (attestedEvidence, error) {
		options, err := verificationOptions(rootOpts, source, "")
		if err != nil {
			return nil, err
		}
		return options.Verifier.VerifyV3(doc, nonce, source)
	}
}

func (o *sandboxOwner) attest(source string) (attestedEvidence, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	input := struct {
		InstanceID string `json:"instance_id"`
		Nonce      string `json:"nonce"`
	}{o.instance, hex.EncodeToString(nonce)}
	var reply relayReply
	if err := o.request(http.MethodPost, "/sandboxes/relay", input, &reply); err != nil {
		return nil, err
	}
	if reply.Status != http.StatusOK {
		return nil, fmt.Errorf("sandbox attestation returned HTTP %d", reply.Status)
	}
	doc, err := decodeB64U(reply.Body, -1)
	if err != nil {
		return nil, err
	}
	verified, err := o.verifyEvidence(doc, nonce, source)
	if err != nil {
		return nil, err
	}
	o.expires = verified.FreshnessExpiresAt()
	return verified, nil
}

// The inner SSH connection owns and closes its Monitor device connection.
type sandboxRouteConn struct {
	net.Conn
	client *ssh.Client
}

func (c *sandboxRouteConn) Close() error {
	return errors.Join(c.Conn.Close(), c.client.Close())
}

func (m *monitorSession) dialSandbox(ctx context.Context, host ssh.PublicKey) (net.Conn, error) {
	device, err := loadSigner(filepath.Join(m.dir, monitorDeviceKeyName))
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: ownerConnectTimeout}).DialContext(ctx, "tcp", m.address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, err := connectOwnerSigner(conn, m.domain, m.hostKey, device, monitorSSHUser)
	if err != nil {
		return nil, err
	}
	route, err := client.DialContext(ctx, "tcp", net.JoinHostPort(routeName(host), strconv.Itoa(defaultSSHPort)))
	if err != nil {
		client.Close()
		return nil, err
	}
	return &sandboxRouteConn{Conn: route, client: client}, nil
}

func (s *sandboxSession) dial(ctx context.Context) (*ssh.Client, error) {
	if !time.Now().Before(s.expires) {
		return nil, errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	var conn net.Conn
	var err error
	if s.monitor != nil {
		conn, err = s.monitor.dialSandbox(ctx, s.profile.hostKey)
	} else {
		address := net.JoinHostPort(s.profile.hostName, strconv.Itoa(s.profile.port))
		conn, err = (&net.Dialer{Timeout: ownerConnectTimeout}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	return connectOwnerSigner(conn, s.box.Domain, s.profile.hostKey, s.keys.signer, sandboxLoginUser)
}

func (o *sandboxOwner) call(ctx context.Context, command string, input, out any) error {
	ctx, cancel := context.WithDeadline(ctx, o.expires)
	defer cancel()
	var body []byte
	if input != nil {
		var err error
		if body, err = json.Marshal(input); err != nil {
			return err
		}
		defer clear(body)
	}
	reply, err := sendOwnerCommand(ctx, o.dial, command, body)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(reply), out)
}

func (s *sandboxSession) install(streams commandIO) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return installSandboxAlias(streams, s.profile, home)
}

func (s *sandboxSession) repinInstalled(streams commandIO) error {
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
		if err := profile.installTo(home, streams.in, streams.err, false, false); err != nil {
			return err
		}
	}
	return nil
}

// Preserve aliases owned by another identity.
func installSandboxAlias(streams commandIO, p sshProfile, home string) error {
	if owned, err := ownsSSHProfile(home, p.name, p.resourceID); err != nil || !owned {
		return errors.Join(err, fmt.Errorf("~/.ssh/tinfoil/%s.conf is the profile of another resource; choose --name ALIAS or remove this profile", p.name))
	}
	return p.installTo(home, streams.in, streams.err, false, true)
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

func (s *sandboxSession) unlockDirect(streams commandIO, ctx context.Context) error {
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	volume, err := sendOwnerCommand(ctx, s.dial, "/usr/local/bin/workspace-unlock --status", nil)
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
	fmt.Fprintln(streams.err, "Unlocking sandbox "+s.box.Name+" encrypted workspace")
	if _, err := sendOwnerCommand(ctx, s.dial, "/usr/local/bin/workspace-unlock --initialize", s.keys.storageKey); err != nil {
		return fmt.Errorf("unlock workspace: %w; retry with `tinfoil sandbox start %s`", err, s.box.Name)
	}
	return nil
}

func sendOwnerCommand(ctx context.Context, dial func(context.Context) (*ssh.Client, error), command string, body []byte) (string, error) {
	return owner.SendCommand(ctx, dial, command, body)
}
