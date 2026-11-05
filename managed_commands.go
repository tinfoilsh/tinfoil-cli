package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const managedKindAnnotation = "managed-kind"

func addManagedCommands(identityOpts *identityOptions, outputOpts *outputOptions, group *cobra.Command) {
	if group.Name() == "monitor" {
		start := newManagedContainerCmd(outputOpts, "monitor", "start")
		start.Short = "Start a stopped or failed Monitor"
		group.AddCommand(start, newMonitorStopCmd(outputOpts), newMonitorDeleteCmd())
	}
	group.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	group.PersistentFlags().StringVar(&identityOpts.attestSSHIdentity, "identity", "", "Owner SSH identity file")
	update := newManagedContainerCmd(outputOpts, group.Name(), "update")
	update.Long = "Review and apply a release update, switching traffic automatically. The shared update plan and downtime confirmation still apply, including with --no-wait."
	metrics := newManagedContainerCmd(outputOpts, group.Name(), "metrics")
	group.AddCommand(update, metrics, newManagedCreateCmd(identityOpts, outputOpts, &waitOptions{}, group.Name()))
}

func newManagedContainerCmd(outputOpts *outputOptions, kind, name string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name + " [id|name]", Args: cobra.ExactArgs(1),
		Annotations: map[string]string{managedKindAnnotation: kind},
	}
	wait := &waitOptions{}
	switch name {
	case "start":
		opts := &containerDeployOptions{}
		cmd.Short = "Deploy a stopped or failed " + kind
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			return runContainerDeploy(opts, outputOpts, wait, cmd, args)
		}
	case "update":
		opts := &containerUpdateOptions{}
		cmd.Short = "Update a running " + kind + " to a new tag or configuration"
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			return runContainerUpdate(opts, outputOpts, wait, cmd, args)
		}
		cmd.Flags().StringVar(&opts.updateTag, "tag", "", "Release tag to update to")
		cmd.Flags().BoolVar(&opts.updateYes, "yes", false, "Approve the update plan, including any downtime")
	case "metrics":
		opts := &containerMetricsOptions{}
		cmd.Short = "Show " + kind + " resource metrics"
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			return runContainerMetrics(opts, cmd, args)
		}
		cmd.Flags().StringVar(&opts.metricsTime, "time", "24h", "Time window (e.g. 1h, 24h, 7d)")
	}
	if name != "metrics" {
		cmd.Flags().BoolVar(&wait.noWait, "no-wait", false, "Return once the request is accepted")
	}
	return cmd
}

func checkManagedKind(kind string, row containerView) error {
	if kind != "" && (row.Repo != managedRepo(kind) || row.Debug) {
		return fmt.Errorf("%s is not a production %s", row.Name, kind)
	}
	return nil
}

// Controlplane stops and deletes a Monitor only together with the sandboxes
// that route through it, since they lose their network without it.
func refuseStandaloneMonitor(row containerView, verb string) error {
	if checkManagedKind("monitor", row) != nil {
		return nil
	}
	return fmt.Errorf("%s is a Monitor; %s it together with its sandboxes with `tinfoil monitor %s %s`", row.Name, verb, verb, row.Name)
}

// resolveOwnMonitor returns a Monitor the caller created and the sandboxes
// that route through it. Only a Monitor's creator can stop or delete it.
func resolveOwnMonitor(scope accountScope, client *cpClient, identifier string) (*containerView, []containerView, error) {
	monitor, err := managedRow(client, "monitor", identifier)
	if err != nil {
		return nil, nil, err
	}
	if monitor.ClerkUserID != scope.UserID {
		return nil, nil, fmt.Errorf("Monitor %s was created by another user; only its creator can stop or delete it", monitor.Name)
	}
	var rows []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
		return nil, nil, err
	}
	sandboxes := slices.DeleteFunc(rows, func(row containerView) bool {
		return row.Repo != defaultSandboxRepo || row.ClerkUserID != monitor.ClerkUserID || !routesThrough(row, monitor.ID)
	})
	return monitor, sandboxes, nil
}

func routesThrough(row containerView, monitorID string) bool {
	return row.NetworkPolicy != nil && slices.ContainsFunc(row.NetworkPolicy.Egress, func(peer containerPeer) bool {
		return strings.EqualFold(peer.ContainerID, monitorID)
	})
}

func containerNames(rows []containerView) string {
	names := make([]string, len(rows))
	for i, row := range rows {
		names[i] = row.Name
	}
	return strings.Join(names, ", ")
}

func newMonitorStopCmd(outputOpts *outputOptions) *cobra.Command {
	return &cobra.Command{
		Use: "stop [id|name]", Short: "Stop a Monitor together with its sandboxes", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, client, err := currentScope()
			if err != nil {
				return err
			}
			monitor, sandboxes, err := resolveOwnMonitor(scope, client, args[0])
			if err != nil {
				return err
			}
			if len(sandboxes) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "Stopping Monitor %s.\n", monitor.Name)
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "Stopping Monitor %s and its sandboxes %s. Their workspaces are kept and still billed for storage.\n", monitor.Name, containerNames(sandboxes))
			}
			if _, err := client.do("POST", pathf("/api/monitors/%s/stop", monitor.ID), nil, nil, nil); err != nil {
				return err
			}
			stopped, err := resolveContainerDetail(client, monitor.ID)
			if err != nil {
				return err
			}
			restart := fmt.Sprintf("Run \"tinfoil monitor start %s\" to bring it back", monitor.Name)
			if len(sandboxes) > 0 {
				restart += ", then \"tinfoil sandbox start NAME\" for each sandbox"
			}
			fmt.Fprintln(cmd.ErrOrStderr(), restart+".")
			return renderContainer(outputOpts, *stopped)
		},
	}
}

func newMonitorDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use: "delete [id|name]", Aliases: []string{"rm", "remove"}, Short: "Delete a Monitor together with its sandboxes and their workspaces", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, client, err := currentScope()
			if err != nil {
				return err
			}
			monitor, sandboxes, err := resolveOwnMonitor(scope, client, args[0])
			if err != nil {
				return err
			}
			deleted := "Monitor " + monitor.Name
			if len(sandboxes) > 0 {
				deleted += " and its sandboxes " + containerNames(sandboxes)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s.\n", deleted)
			if len(sandboxes) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "This permanently deletes the Monitor and all of its data.")
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "This permanently deletes them, with the sandboxes' workspaces and all of their data.")
			}
			if err := confirmYes(yes, cmd.CommandPath()); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/monitors/%s", monitor.ID), nil, nil, nil); err != nil {
				return err
			}
			var forgetErr error
			for _, sandbox := range sandboxes {
				forgetErr = errors.Join(forgetErr, forgetSandbox(sandbox.Name, sandbox.ID))
			}
			if forgetErr != nil {
				return fmt.Errorf("deleted %s, but %w", deleted, forgetErr)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Saved encryption credentials are kept.\n", deleted)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	return cmd
}

func newManagedCreateCmd(identityOpts *identityOptions, outputOpts *outputOptions, waitOpts *waitOptions, kind string) *cobra.Command {
	var tag, publicKey, monitor, workspace string
	var workspaceSize int
	cmd := &cobra.Command{
		Use: "create NAME", Short: "Create a confidential " + kind + " and follow its deployment", Args: cobra.ExactArgs(1),
		Long: `Needs "tinfoil login --sync" unless --owner-public-key or --identity is set;
with those, storage keys are created on first open and kept only on that machine.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(tag) == "" {
				return errors.New("choose --tag from `tinfoil repo build info " + managedRepo(kind) + "`")
			}
			sizeChosen := cmd.Flags().Changed("workspace-size")
			if sizeChosen && workspace != "" {
				return errors.New("--workspace-size cannot be combined with --workspace; a reused workspace keeps its size")
			}
			if sizeChosen && !slices.Contains(sandboxWorkspaceSizesGB, workspaceSize) {
				return fmt.Errorf("--workspace-size must be %s (GB)", workspaceSizeChoices(""))
			}
			scope, client, err := currentScope()
			if err != nil {
				return err
			}
			variables := map[string]string{}
			body := map[string]any{"name": strings.TrimSpace(args[0]), "repo": managedRepo(kind), "tag": strings.TrimSpace(tag), "variables": variables}
			userKeys := publicKey != "" || identityOpts.attestSSHIdentity != ""
			if kind == "sandbox" {
				selected, err := selectCreationMonitor(client, monitor, scope.UserID)
				if err != nil {
					return err
				}
				if selected.OwnerKeyMode == "umk" && !userKeys {
					return fmt.Errorf("Monitor %s uses your own keys, so its sandboxes must too; pass --owner-public-key FILE", selected.Name)
				}
				variables["SANDBOX_INSTANCE_ID"] = uuid.NewString()
				body["network_policy"] = sandboxNetworkPolicy(selected.ID)
				if workspace != "" {
					volume, err := lookupSandboxWorkspace(client, workspace)
					if err != nil {
						return err
					}
					if volume.ContainerID != "" {
						return fmt.Errorf("volume %s is already attached to %s; stop and detach it before reuse", workspace, volumeContainerLabel(*volume))
					}
					body["volumes"] = map[string]string{sandboxWorkspaceSlot: volume.ID}
				}
				if sizeChosen {
					body["workspace_size_gb"] = workspaceSize
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Monitor: %s (%s). Service access requires it to be running and unlocked.\n", selected.Name, statusLabel(selected.Status))
			} else {
				body["object_storage"] = map[string]any{}
			}
			mode, owner, err := prepareResourceKeys(identityOpts, cmd.Context(), client, scope, kind, userKeys, publicKey)
			if err != nil {
				return err
			}
			body["owner_key_mode"], body["owner_public_key"] = mode, owner
			fmt.Fprintln(cmd.ErrOrStderr(), "Creating and publishing configuration. Storage remains billable until deleted.")
			var created containerView
			if _, err := client.do("POST", "/api/containers", nil, body, &created); err != nil {
				return fmt.Errorf("%w; inspect `tinfoil %s status` before retrying creation", err, kind)
			}
			// Provisioning and storage attachment belong to Controlplane. Follow
			// the returned deployment exactly like an ordinary container.
			return createFollowupError(created, "", followAndRender(outputOpts, waitOpts, client, created, nil))
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "Published release tag [required]")
	cmd.Flags().StringVar(&publicKey, "owner-public-key", "", "Use your own Ed25519 public key file instead of synced keys")
	cmd.Flags().BoolVar(&waitOpts.noWait, "no-wait", false, "Return after creation without following boot progress")
	if kind == "sandbox" {
		cmd.Flags().StringVar(&monitor, "monitor", "", "Monitor name or ID (required when more than one exists)")
		cmd.Flags().StringVar(&workspace, "workspace", "", "Reuse an unattached workspace volume by name or ID")
		cmd.Flags().IntVar(&workspaceSize, "workspace-size", 0, fmt.Sprintf("New workspace volume size in GB: %s (default %d)", workspaceSizeChoices(""), defaultWorkspaceSizeGB))
	}
	return cmd
}

// Pairing a sandbox needs the Monitor creator's local credentials, so
// Controlplane only attaches sandboxes to Monitors with the same creator.
func selectCreationMonitor(client *cpClient, identifier, userID string) (*containerView, error) {
	if identifier == "" {
		var rows []containerView
		if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
			return nil, err
		}
		rows = slices.DeleteFunc(rows, func(row containerView) bool {
			return checkManagedKind("monitor", row) != nil || row.ClerkUserID != userID
		})
		switch len(rows) {
		case 0:
			return nil, errors.New("you have no Monitors in this account; create one with `tinfoil monitor create NAME`, since sandboxes cannot use Monitors created by other users")
		case 1:
			identifier = rows[0].ID
		default:
			return nil, fmt.Errorf("choose one of your Monitors with --monitor: %s", containerNames(rows))
		}
	}
	row, err := managedRow(client, "monitor", identifier)
	if err == nil && !looksLikeUUID(row.ID) {
		err = errors.New("invalid Monitor UUID")
	}
	if err == nil && row.ClerkUserID != userID {
		err = fmt.Errorf("Monitor %s was created by another user, and sandboxes can only use Monitors you created; choose one of yours or create one with `tinfoil monitor create NAME`", row.Name)
	}
	return row, err
}

func prepareResourceKeys(identityOpts *identityOptions, ctx context.Context, client *cpClient, scope accountScope, kind string, userKeys bool, publicKey string) (string, string, error) {
	if !userKeys {
		mk, err := newMKSession(client, scope)
		if err != nil {
			return "", "", fmt.Errorf("%w, or create it with your own key using --owner-public-key FILE", err)
		}
		key := newResourceKey(kind)
		defer clear(key.OwnerSeed)
		defer clear(key.StorageKey)
		defer clear(key.MonitorIdentitySeed)
		if _, err := mk.update(ctx, func(p *mkPayload) error { return addKey(p, key) }); err != nil {
			return "", "", err
		}
		return "tmk", key.OwnerPublicKey, nil
	}
	owner, err := creationOwnerKey(publicKey, identityOpts.attestSSHIdentity)
	if err != nil {
		return "", "", err
	}
	return "umk", owner, nil
}

func creationOwnerKey(publicFile, identity string) (string, error) {
	if publicFile == "" {
		publicFile = "~/.ssh/id_ed25519.pub"
		if identity != "" {
			publicFile = strings.TrimSuffix(identity, ".pub") + ".pub"
		}
	}
	if strings.HasPrefix(publicFile, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		publicFile = filepath.Join(home, publicFile[2:])
	}
	raw, err := os.ReadFile(publicFile)
	if err != nil {
		return "", fmt.Errorf("read owner public key: %w; select an Ed25519 public key with --owner-public-key FILE", err)
	}

	key, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return "", errors.New("owner must be one Ed25519 SSH public key without authorized_keys options")
	}
	public := key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	return "ed25519:" + base64.StdEncoding.EncodeToString(public), nil
}

func managedRepo(kind string) string {
	return map[string]string{"monitor": monitorRepo, "sandbox": defaultSandboxRepo}[kind]
}

func managedRow(client *cpClient, kind, identifier string) (*containerView, error) {
	row, err := resolveContainerDetail(client, identifier)
	if err != nil {
		return nil, err
	}
	if err := checkManagedKind(kind, *row); err != nil {
		return nil, err
	}
	return row, nil
}

func newManagedStatusCmd(outputOpts *outputOptions, kind string) *cobra.Command {
	var watch bool
	cmd := &cobra.Command{
		Use: "status [id|name]", Aliases: []string{"get", "list", "ls"}, Short: "Show status, boot details and connection instructions", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if len(args) == 0 && errors.Is(err, errNotLoggedIn) {
				plural := map[string]string{"monitor": "monitors", "sandbox": "sandboxes"}[kind]
				fmt.Fprintf(cmd.OutOrStdout(), "No %s are stored on this machine. Run `tinfoil login` to list your account's %s.\n", plural, plural)
				return nil
			}
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if watch {
					return fmt.Errorf("choose a %s name or ID to watch", kind)
				}
				return listContainers(outputOpts, client, kind)
			}
			row, err := managedRow(client, kind, args[0])
			if err != nil {
				return err
			}
			if !watch {
				// JSON output carries no volume details, so it skips the volume list.
				var attached map[string]volumeView
				if outputOpts.outputFormat != "json" {
					if attached, err = loadContainerVolumes(client, *row); err != nil {
						return err
					}
				}
				return renderContainerDetail(outputOpts, *row, attached)
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			var previous *containerView
			_, err = pollContainer(ctx, client, row.ID, *row, 0, func(current containerView) (bool, error) {
				if err := checkManagedKind(kind, current); err != nil {
					return false, err
				}
				if previous != nil && reflect.DeepEqual(*previous, current) {
					return false, nil
				}
				previous = &current
				return false, renderContainer(outputOpts, current)
			})
			if ctx.Err() == context.Canceled {
				return nil
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&watch, "watch", false, "Watch this VM's status and boot details until Ctrl-C")
	return cmd
}

func printBootStages(out io.Writer, stages []bootStage) {
	for _, stage := range stages {
		if len(stage.Stages) > 0 {
			printBootStages(out, stage.Stages)
			continue
		}
		fmt.Fprintf(out, "Boot:         %s: %s", stage.Name, stage.Status)
		if stage.Detail != "" {
			fmt.Fprintf(out, " — %s", stage.Detail)
		}
		fmt.Fprintln(out)
	}
}
