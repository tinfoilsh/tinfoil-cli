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

func init() {
	monitorCmd.AddCommand(newManagedStatusCmd("monitor"))
	start := newManagedContainerCmd("monitor", "start", containerDeployCmd, "no-wait")
	start.Short = "Start a stopped or failed Monitor using its saved configuration"
	remove := newManagedContainerCmd("monitor", "delete", containerDeleteCmd, "yes")
	deleteMonitor := remove.RunE
	remove.RunE = func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		row, err := managedRow(client, "monitor", args[0])
		if err != nil {
			return err
		}
		if err := deleteMonitor(cmd, args); err != nil {
			return err
		}
		scope, _, err := currentScope()
		if err == nil {
			err = forgetDeletedResource(cmd.Context(), client, scope, *row)
		}
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Its keys are kept: %v\n", err)
		}
		return nil
	}
	monitorCmd.AddCommand(start, newManagedContainerCmd("monitor", "stop", containerStopCmd), remove)
	for _, group := range []*cobra.Command{sandboxCmd, monitorCmd} {
		group.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
		group.PersistentFlags().StringVar(&attestSSHIdentity, "identity", "", "Owner SSH identity file")
		update := newManagedContainerCmd(group.Name(), "update", containerUpdateCmd, "tag", "yes", "no-wait")
		update.Long = "Review and apply a release update, switching traffic automatically. The shared update plan and downtime confirmation still apply, including with --no-wait."
		group.AddCommand(update, newManagedCreateCmd(group.Name()))
	}
}

// Reuse the handler and its flag values. Each entry point owns its Cobra
// metadata, including Changed, so setting an alias flag cannot mark the
// original command's flag as explicitly supplied.
func newManagedContainerCmd(kind, name string, source *cobra.Command, flags ...string) *cobra.Command {
	cmd := &cobra.Command{
		Use: name + " [id|name]", Short: strings.ReplaceAll(source.Short, "container", kind),
		Aliases: source.Aliases, Args: source.Args, RunE: source.RunE,
		Annotations: map[string]string{managedKindAnnotation: kind}, SilenceUsage: true,
	}
	for _, name := range flags {
		flag := *source.Flags().Lookup(name)
		flag.Changed = false
		cmd.Flags().AddFlag(&flag)
	}
	return cmd
}

func checkManagedKind(kind string, row containerView) error {
	if kind != "" && (row.Repo != managedRepo(kind) || row.Debug) {
		return fmt.Errorf("%s is not a production %s", row.Name, kind)
	}
	return nil
}

func newManagedCreateCmd(kind string) *cobra.Command {
	var tag, publicKey, monitor, workspace string
	var workspaceSize int
	cmd := &cobra.Command{
		Use: "create NAME", Short: "Create a confidential " + kind + " and follow its deployment", Args: cobra.ExactArgs(1),
		Long: "Create from a published release. By default the CLI generates the resource's own owner, storage and agent keys and saves them in your synced key bundle (requires `tinfoil login --sync`) before creating it. With --owner-public-key or --identity, the resource uses your own Ed25519 key (one distinct key per resource), and its storage keys are generated and kept only on this machine; back them up. Inspect interrupted creation with status; use start to retry a stopped or failed resource. Compute is billed while running; storage remains billable until deleted.",
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
			userKeys := publicKey != "" || attestSSHIdentity != ""
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
					body["volumes"] = map[string]string{"workspace": volume.ID}
				}
				if sizeChosen {
					body["workspace_size_gb"] = workspaceSize
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Monitor: %s (%s). Service access requires it to be running and unlocked.\n", selected.Name, statusLabel(selected.Status))
			} else {
				body["object_storage"] = map[string]any{}
			}
			// Keys are saved before allocation; a lost create reply is reconciled
			// through inventory by this owner key, never by resubmitting.
			mode, owner, err := prepareResourceKeys(cmd.Context(), client, scope, kind, userKeys, publicKey)
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
			return createFollowupError(created, "", followAndRender(client, created, nil))
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "Published release tag [required]")
	cmd.Flags().StringVar(&publicKey, "owner-public-key", "", "Use your own Ed25519 public key file instead of synced keys (one distinct key per resource)")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Return after creation without following boot progress")
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
			names := make([]string, len(rows))
			for i, row := range rows {
				names[i] = row.Name
			}
			return nil, fmt.Errorf("choose one of your Monitors with --monitor: %s", strings.Join(names, ", "))
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

// prepareResourceKeys saves a new resource's keys before it is created: synced keys
// in the key bundle, or a registered user key with locally generated storage keys.
func prepareResourceKeys(ctx context.Context, client *cpClient, scope accountScope, kind string, userKeys bool, publicKey string) (string, string, error) {
	if !userKeys {
		mk, err := newMKSession(client, scope)
		if err != nil {
			return "", "", fmt.Errorf("%w, or create it with your own key using --owner-public-key FILE", err)
		}
		key := newResourceKey(kind)
		defer clear(key.OwnerSeed)
		defer clear(key.StorageKey)
		defer clear(key.AgentSeed)
		if _, err := mk.update(ctx, func(p *mkPayload) error { return addKey(p, key) }); err != nil {
			return "", "", err
		}
		return "tmk", key.OwnerPublicKey, nil
	}
	owner, err := creationOwnerKey(publicKey, attestSSHIdentity)
	if err != nil {
		return "", "", err
	}
	if err := registerUMK(ctx, client, kind, owner); err != nil {
		return "", "", err
	}
	path, err := umkRecordPath(scope, owner)
	if err != nil {
		return "", "", err
	}
	record := newUMKRecord(kind, owner)
	defer clear(record.StorageKey)
	defer clear(record.AgentSeed)
	if _, err := saveUMKRecord(path, record); err != nil {
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

func newManagedStatusCmd(kind string) *cobra.Command {
	var watch bool
	cmd := &cobra.Command{
		Use: "status [id|name]", Aliases: []string{"get", "list", "ls"}, Short: "Show status, boot details and connection instructions", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if len(args) == 0 && errors.Is(err, errNotLoggedIn) {
				fmt.Fprintf(cmd.OutOrStdout(), "No %ss are stored on this machine. Run `tinfoil login` to list your account's %ss.\n", kind, kind)
				return nil
			}
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if watch {
					return fmt.Errorf("choose a %s name or ID to watch", kind)
				}
				return listContainers(client, kind)
			}
			row, err := managedRow(client, kind, args[0])
			if err != nil {
				return err
			}
			if !watch {
				// JSON output carries no volume details, so it skips the volume list.
				var attached map[string]volumeView
				if outputFormat != "json" {
					if attached, err = loadContainerVolumes(client, *row); err != nil {
						return err
					}
				}
				return renderContainerDetail(*row, attached)
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
				return false, renderContainer(current)
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
