package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
)

const (
	defaultSandboxRepo = owner.DefaultSandboxRepo
	sandboxLoginUser   = owner.SandboxLoginUser
	sandboxOwnerEnv    = owner.SandboxOwnerEnv
	tmkOwnerKeyName    = owner.TMKOwnerKeyName
	monitorSSHUser     = owner.MonitorSSHUser
	monitorJumpSuffix  = owner.MonitorJumpSuffix
	// Controlplane gives a new sandbox this workspace size when none is chosen.
	defaultWorkspaceSizeGB = 16
	// sandboxWorkspaceSlot is the volume mount that holds a sandbox's workspace.
	sandboxWorkspaceSlot = owner.SandboxWorkspaceSlot
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

func newSandboxCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions) *cobra.Command {
	sandboxCmd := &cobra.Command{
		Use: "bunker", Short: "Manage your confidential bunkers",
	}
	sandboxCmd.AddCommand(newSandboxStatusCommand(pollingOpts, newClient, outputOpts), newSandboxStartCommand(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxRestartCommand(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxStopCommand(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}), newSandboxDeleteCommand(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, &sandboxActionOptions{}, &trustOptions{}))
	return sandboxCmd
}

func newSandboxStatusCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	sandboxStatusCmd := newManagedStatusCmd(pollingOpts, newClient, outputOpts, "sandbox")

	return sandboxStatusCmd
}

func newSandboxStartCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxStartCmd := &cobra.Command{
		Use: "start [id|name]", Short: "Start a bunker and enroll this machine's keys",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "start"),
	}
	addTrustDangerousFlag(trustOpts, sandboxStartCmd)
	sandboxStartCmd.Flags().Bool("no-enroll", false, "Boot without unlocking or enrolling this machine's keys")
	return sandboxStartCmd
}
func newSandboxRestartCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxRestartCmd := &cobra.Command{
		Use: "restart [id|name]", Short: "Restart a bunker and enroll this machine's keys",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "restart"),
	}
	addTrustDangerousFlag(trustOpts, sandboxRestartCmd)
	sandboxRestartCmd.Flags().Bool("no-enroll", false, "Boot without unlocking or enrolling this machine's keys")
	return sandboxRestartCmd
}
func newSandboxStopCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxStopCmd := &cobra.Command{
		Use: "stop [id|name]", Short: "Stop a bunker, keeping its workspace",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "stop"),
	}

	return sandboxStopCmd
}
func newSandboxDeleteCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions) *cobra.Command {
	sandboxDeleteCmd := &cobra.Command{
		Use: "delete [id|name]", Short: "Delete a bunker and its workspace volume",
		Args: cobra.ExactArgs(1), RunE: runSandboxAction(pollingOpts, newClient, newScope, identityOpts, outputOpts, rootOpts, sandboxActionOpts, trustOpts, "delete"),
	}
	sandboxDeleteCmd.Flags().BoolVar(&sandboxActionOpts.sandboxYes, "yes", false, "Skip the confirmation prompt")
	return sandboxDeleteCmd
}

func runSandboxAction(pollingOpts *pollingOptions, newClient authenticatedClientFactory, newScope scopeClientFactory, identityOpts *identityOptions, outputOpts *outputOptions, rootOpts *rootOptions, sandboxActionOpts *sandboxActionOptions, trustOpts *trustOptions, action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client, err := newClient(commandStreams(cmd))
		if err != nil {
			return err
		}
		row, err := managedRow(client, "sandbox", args[0])
		if action == "delete" && missingContainer(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Bunker %s is already deleted. Saved encryption credentials are kept.\n", args[0])
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
				fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s permanently deletes its workspace volume and all of its data. To keep the workspace, stop the bunker and run `tinfoil volume detach %s` before deleting it.\n", row.Name, workspace)
			}
			if err := confirmYes(commandStreams(cmd), sandboxActionOpts.sandboxYes, "bunker delete"); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/containers/%s", row.ID), nil, nil, nil); err != nil && !missingContainer(err) {
				return err
			}
			if err := forgetSandbox(commandStreams(cmd), newScope, row.Name, row.ID); err != nil {
				return fmt.Errorf("%s is deleted, but %w", row.Name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Saved encryption credentials are kept. Remove any access grants in the Perimeter UI.\n", deleted)
			return nil
		case "stop":
			stopped, err := stopContainer(pollingOpts, client, *row)
			if err != nil {
				return err
			}
			return renderContainer(commandStreams(cmd), outputOpts, stopped)
		case "start", "restart":
			started, err := startSandboxRow(pollingOpts, commandStreams(cmd), client, *row, action == "restart")
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
		s, err := connectSandbox(newScope, commandStreams(cmd), identityOpts, rootOpts, trustOpts, cmd.Context(), target)
		if err != nil {
			return err
		}
		defer s.close()
		if err := s.enroll(cmd.Context()); err != nil {
			return err
		}
		if err := s.install(commandStreams(cmd)); err != nil {
			return fmt.Errorf("%s was enrolled, but its ssh profile was not installed: %w; retry `tinfoil bunker start %s`", target.Name, err, target.Name)
		}
		return renderContainer(commandStreams(cmd), outputOpts, *row)
	}
}

func startSandboxRow(pollingOpts *pollingOptions, streams commandIO, client *cpClient, row containerView, restart bool) (containerView, error) {
	if restart || row.Status == statusStopped || row.Status == statusFailed {
		if err := validateSandboxNetwork(row); err != nil {
			return row, err
		}
		var err error
		if restart {
			row, err = stopContainer(pollingOpts, client, row)
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
		return followContainer(pollingOpts, streams, client, row.ID, row)
	}
	return row, nil
}

func sandboxNetworkPolicy(monitorID string) containerNetworkPolicy {
	return containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: monitorID, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}
}
func sandboxNetworkMatches(row containerView) bool { return owner.SandboxNetworkMatches(row) }
func validateSandboxNetwork(row containerView) error {
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	return owner.ValidateSandboxNetwork(row, env)
}
func sandboxBinding(scope accountScope, target *workloadTarget) (keybundle.Binding, error) {
	return owner.SandboxBinding(owner.Scope(scope), ownerWorkload(target))
}

type sandboxSession struct {
	*owner.Sandbox
	profile sshProfile
}

func (s *sandboxSession) close() { s.Close() }
func (s *sandboxSession) enroll(ctx context.Context) error {
	return humanControlplaneError(s.Enroll(ctx))
}

func connectSandbox(newScope scopeClientFactory, streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, ctx context.Context, target *workloadTarget) (_ *sandboxSession, err error) {
	scope, cp, err := newScope(streams)
	if err != nil {
		return nil, err
	}
	row := target.containerView
	if _, err := sandboxBinding(scope, target); err != nil {
		return nil, err
	}
	var monitor *monitorSession
	defer func() {
		if err != nil && monitor != nil {
			monitor.close()
		}
	}()
	if target.env["NO_MONITOR"] != "1" {
		fmt.Fprintln(streams.err, "Checking the selected Perimeter for bunker "+row.Name)
		peer, err := resolveContainerDetail(cp, row.NetworkPolicy.Egress[0].ContainerID)
		if err != nil {
			return nil, fmt.Errorf("bunker %s's Perimeter: %w", row.Name, err)
		}
		selected, err := resolveWorkload(streams, rootOpts, trustOpts, *peer, monitorRepo, "")
		if err != nil {
			return nil, fmt.Errorf("selected Perimeter %s: %w; review its configuration with `tinfoil perimeter open %s`", peer.Name, err, peer.Name)
		}
		if peer.OwnerKeyMode == "umk" && row.OwnerKeyMode == "tmk" {
			return nil, fmt.Errorf("a UMK Perimeter cannot serve the synced bunker %s", row.Name)
		}
		if monitor, err = connectMonitorOwner(streams, identityOpts, rootOpts, ctx, scope, cp, selected, true); err != nil {
			return nil, err
		}
	}
	service, err := ownerService(streams, identityOpts, cp)
	if err != nil {
		return nil, err
	}
	var m *owner.Monitor
	if monitor != nil {
		m = monitor.Monitor
	}
	s, err := service.OpenSandbox(ctx, owner.Scope(scope), cp.transport(), ownerWorkload(target), m, ownerVerifier{streams, rootOpts})
	if err != nil {
		return nil, humanControlplaneError(err)
	}
	return &sandboxSession{Sandbox: s, profile: ownerSSHProfile(s.Connection())}, nil
}

func relinkSandboxes(streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, ctx context.Context, scope accountScope, cp *cpClient, m *monitorSession, monitorID string) []error {
	var rows []containerView
	if _, err := cp.doContext(ctx, "GET", "/api/containers", nil, nil, nil, &rows); err != nil {
		return []error{fmt.Errorf("listing bunkers to re-link: %w", err)}
	}
	var failures []error
	for _, listed := range rows {
		if listed.Repo != defaultSandboxRepo || listed.Debug || listed.Status != statusRunning || listed.ClerkUserID != scope.UserID || !sandboxNetworkMatches(listed) || listed.NetworkPolicy.Egress[0].ContainerID != monitorID {
			continue
		}
		if err := relinkSandbox(streams, identityOpts, rootOpts, trustOpts, ctx, scope, cp, m, monitorID, listed.ID); err != nil && !errors.As(err, new(noLocalKeys)) {
			failures = append(failures, fmt.Errorf("bunker %s: %w", listed.Name, err))
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
	if err := m.ValidateSandboxCustody(*row); err != nil {
		return err
	}
	target, err := resolveWorkload(streams, rootOpts, trustOpts, *row, defaultSandboxRepo, "")
	if err != nil {
		return err
	}
	service, err := ownerService(streams, identityOpts, cp)
	if err != nil {
		return err
	}
	connection, err := service.RelinkSandbox(ctx, owner.Scope(scope), cp.transport(), m.Monitor, monitorID, id, ownerWorkload(target), ownerVerifier{streams, rootOpts})
	if err != nil || connection == nil {
		return humanControlplaneError(err)
	}
	s := &sandboxSession{profile: ownerSSHProfile(*connection)}
	return s.repinInstalled(streams)
}

func ownerSSHProfile(info owner.ConnectionInfo) sshProfile {
	p := sshProfile{resourceID: info.ResourceID, name: info.Name, hostName: info.HostName, port: info.Port, user: info.User, identityFile: info.IdentityFile, hostKey: info.HostKey, hostKeyAlias: info.HostKeyAlias, noAgent: info.NoAgent}
	if info.Jump != nil {
		jump := ownerSSHProfile(*info.Jump)
		p.jump = &jump
	}
	return p
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
func forgetSandbox(streams commandIO, newScope scopeClientFactory, name, id string) error {
	if id == "" {
		return nil
	}
	scope, _, err := newScope(streams)
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
