package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const sandboxWorkspaceBytes int64 = 30 * 1024 * 1024 * 1024

func init() {
	monitorCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	monitorCmd.PersistentFlags().StringVar(&attestSSHIdentity, "identity", "", "Owner SSH identity file")
	for _, group := range []*cobra.Command{sandboxCmd, monitorCmd} {
		kind := group.Name()
		group.AddCommand(newManagedCreateCmd(kind), newManagedResumeCmd(kind), newManagedPendingCmd(kind))
	}
}

func newManagedCreateCmd(kind string) *cobra.Command {
	var tag, publicKey, monitor, workspace string
	var noWait bool
	cmd := &cobra.Command{
		Use: "create NAME", Short: "Create a confidential " + kind + " and wait for it to boot", Args: cobra.ExactArgs(1),
		Long: "Create using a published release and an Ed25519 owner public key. Private keys stay local. Interrupted creation is saved per account: use pending, resume, or pending clear. Compute is billed while running; storage remains billable until deleted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if strings.TrimSpace(tag) == "" {
				return errors.New("choose --tag from `tinfoil repo build info " + managedRepo(kind) + "`")
			}
			if !managedNamePattern.MatchString(name) {
				return errors.New("use lowercase letters, digits or dashes, starting and ending with a letter or digit, up to 63 characters")
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			scope, client, err := currentScope()
			if err != nil {
				return err
			}
			path, err := pendingCreationPath(scope)
			if err != nil {
				return err
			}
			unlock, err := acquireStorageLock(path)
			if err != nil {
				return err
			}
			defer unlock()
			if p, err := readPendingCreation(path, scope); err == nil {
				return fmt.Errorf("%s %s has a pending creation; run `tinfoil %s resume` or inspect `tinfoil %s pending`", p.Kind, p.Name, p.Kind, kind)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			var rows []containerView
			if _, err := client.doContext(ctx, "GET", "/api/containers", nil, nil, nil, &rows); err != nil {
				return err
			}
			for _, row := range rows {
				if row.Name == name {
					return fmt.Errorf("name %q already belongs to a VM in this account (%s)", name, row.ID)
				}
			}
			p := pendingCreation{Version: 1, Scope: scope, Kind: kind, Name: name, Tag: strings.TrimSpace(tag)}
			fallbackOwner := ""
			if kind == "sandbox" {
				selected, err := selectCreationMonitor(client, rows, monitor)
				if err != nil {
					return err
				}
				env, err := measuredEnvironment(selected.Config)
				if err != nil {
					return err
				}
				if _, err := measuredOwner(env[monitorOwnerEnv]); err != nil {
					return fmt.Errorf("Monitor %s: %w", selected.Name, err)
				}
				p.Monitor = &monitorBinding{ContainerID: selected.ID, Owner: env[monitorOwnerEnv]}
				fallbackOwner = p.Monitor.Owner
				fmt.Fprintf(cmd.ErrOrStderr(), "Monitor: %s (%s).\n", selected.Name, statusLabel(selected.Status))
				if selected.Status != statusRunning {
					fmt.Fprintln(cmd.ErrOrStderr(), "Service access will wait until this Monitor is running and unlocked.")
				}
				if workspace != "" {
					volume, err := lookupVolume(client, workspace)
					if err != nil {
						return err
					}
					p.Workspace = volume.ID
				}
			}
			p.Owner, err = creationOwnerKey(publicKey, attestSSHIdentity, fallbackOwner)
			if err != nil {
				return err
			}
			instance := make([]byte, 16)
			if _, err := rand.Read(instance); err != nil {
				return err
			}
			instance[6], instance[8] = (instance[6]&0x0f)|0x40, (instance[8]&0x3f)|0x80
			p.Instance = fmt.Sprintf("%x-%x-%x-%x-%x", instance[:4], instance[4:6], instance[6:8], instance[8:10], instance[10:])
			if err := validatePendingCreation(p, scope); err != nil {
				return err
			}
			key, _ := measuredOwner(p.Owner)
			fmt.Fprintf(cmd.ErrOrStderr(), "Creating %s %s with %s. Owner: %s\n", kind, p.Name, p.Tag, ssh.FingerprintSHA256(key))
			fmt.Fprintln(cmd.ErrOrStderr(), "Compute is billed while running; resource sizes come from the selected release. Storage remains billable until deleted.")
			if err := writeStorageJSON(path, p, true); err != nil {
				return err
			}
			return finishManagedCreation(ctx, cmd, client, path, &p, noWait)
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "Published release tag (see tinfoil repo build info) [required]")
	cmd.Flags().StringVar(&publicKey, "owner-public-key", "", "Ed25519 public key file (default: Monitor owner for sandbox, otherwise ~/.ssh/id_ed25519.pub)")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Return after creation; retain pending intent until resume verifies boot")
	if kind == "sandbox" {
		cmd.Flags().StringVar(&monitor, "monitor", "", "Monitor name or ID (required when more than one exists)")
		cmd.Flags().StringVar(&workspace, "workspace", "", "Reuse an unattached workspace volume by name or ID (at least 30 GiB)")
	}
	return cmd
}

func newManagedResumeCmd(kind string) *cobra.Command {
	var noWait bool
	cmd := &cobra.Command{
		Use: "resume", Short: "Resume this account's saved " + kind + " creation", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			scope, client, err := currentScope()
			if err != nil {
				return err
			}
			path, err := pendingCreationPath(scope)
			if err != nil {
				return err
			}
			unlock, err := acquireStorageLock(path)
			if err != nil {
				return err
			}
			defer unlock()
			p, err := readPendingCreation(path, scope)
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("no pending creation in this account")
			}
			if err != nil {
				return err
			}
			if p.Kind != kind {
				return fmt.Errorf("pending creation is a %s; use `tinfoil %s resume`", p.Kind, p.Kind)
			}
			return finishManagedCreation(ctx, cmd, client, path, &p, noWait)
		},
	}
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Check saved creation without waiting for boot")
	return cmd
}

func selectCreationMonitor(client *cpClient, rows []containerView, identifier string) (*containerView, error) {
	if identifier == "" {
		var names []string
		for _, row := range rows {
			if row.Repo == monitorRepo && !row.Debug {
				identifier = row.ID
				names = append(names, row.Name)
			}
		}
		if len(names) == 0 {
			return nil, errors.New("no Monitor in this account; run `tinfoil monitor create NAME` first")
		}
		if len(names) > 1 {
			return nil, fmt.Errorf("choose --monitor from: %s", strings.Join(names, ", "))
		}
	}
	row, err := resolveContainerDetail(client, identifier)
	if err != nil {
		return nil, err
	}
	if row.Repo != monitorRepo || row.Debug || !looksLikeUUID(row.ID) {
		return nil, errors.New("selected resource is not a production Monitor")
	}
	return row, nil
}

func creationOwnerKey(publicFile, identity, fallback string) (string, error) {
	if publicFile == "" && identity == "" && fallback != "" {
		return fallback, nil
	}
	if publicFile == "" {
		if identity != "" {
			publicFile = identity
			if !strings.HasSuffix(publicFile, ".pub") {
				publicFile += ".pub"
			}
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			publicFile = filepath.Join(home, ".ssh", "id_ed25519.pub")
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
	if strings.Contains(string(raw), "PRIVATE KEY") {
		return "", errors.New("--owner-public-key requires a public key, never a private key")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return "", errors.New("owner must be one Ed25519 SSH public key without authorized_keys options")
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return "", errors.New("invalid Ed25519 public key")
	}
	public, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("invalid Ed25519 public key")
	}
	return "ed25519:" + base64.StdEncoding.EncodeToString(public), nil
}

func workspaceUnavailable(v volumeView) string {
	if v.BillingEndedAt != "" {
		return "deleted"
	}
	if v.ContainerID != "" {
		return "attached to " + v.ContainerID
	}
	if v.SizeBytes < sandboxWorkspaceBytes {
		return "too small (requires at least 30 GiB / 32.21 GB)"
	}
	return ""
}

func checkCreationWorkspace(ctx context.Context, client *cpClient, id string, out io.Writer) error {
	var storage volumeList
	if _, err := client.doContext(ctx, "GET", "/api/volumes", nil, nil, nil, &storage); err != nil {
		return err
	}
	if id != "" {
		for _, v := range storage.Volumes {
			if v.ID == id {
				if reason := workspaceUnavailable(v); reason != "" {
					return fmt.Errorf("workspace %s is %s; choose an unattached workspace", v.Name, reason)
				}
				fmt.Fprintf(out, "Reusing workspace %s (%s) on its current host. Keep its original encryption credentials; your SSH key alone cannot unlock existing data. Storage remains billable until deleted.\n", v.Name, formatSize(v.SizeBytes))
				return nil
			}
		}
		return errors.New("selected workspace is unavailable in this account")
	}
	if !storage.CanCreateVolumes || storage.AvailableBytes < sandboxWorkspaceBytes ||
		(!storage.BillingExempt && (storage.StorageGiBPerHour == nil || *storage.StorageGiBPerHour < 0 || math.IsNaN(*storage.StorageGiBPerHour) || math.IsInf(*storage.StorageGiBPerHour, 0))) {
		return errors.New("new workspace capacity or pricing unavailable; use --workspace with an existing unattached volume (inspect `tinfoil volume list`)")
	}
	rate := "billing exempt"
	if !storage.BillingExempt {
		rate = fmt.Sprintf("$%.8g/GB-hour", *storage.StorageGiBPerHour/(float64(1<<30)/1e9))
	}
	fmt.Fprintf(out, "New workspace: 30 GiB (32.21 GB), %s; %.2f GB capacity available.\n", rate, float64(storage.AvailableBytes)/1e9)
	return nil
}

func finishManagedCreation(ctx context.Context, cmd *cobra.Command, client *cpClient, path string, p *pendingCreation, noWait bool) error {
	row, complete, err := provisionManaged(ctx, client, path, p, noWait, cmd.ErrOrStderr())
	if err != nil {
		return fmt.Errorf("%w; creation record kept: inspect `tinfoil %s pending`, then `tinfoil %s resume`", err, p.Kind, p.Kind)
	}
	if complete {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("%s is running but could not clear pending creation: %w", p.Name, err)
		}
		if p.Kind == "monitor" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Open and unlock: tinfoil monitor open %s\n", p.Name)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Connect and unlock: tinfoil attest-ssh %s --install && ssh %s\n", p.Name, p.Name)
		}
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Creation saved. Finish with: tinfoil %s resume\n", p.Kind)
	}
	return renderContainer(row)
}

func provisionManaged(ctx context.Context, client *cpClient, path string, p *pendingCreation, noWait bool, out io.Writer) (containerView, bool, error) {
	var row containerView
	if err := validatePendingCreation(*p, p.Scope); err != nil {
		return row, false, err
	}
	found := p.ID != ""
	if !found {
		var rows []containerView
		if _, err := client.doContext(ctx, "GET", "/api/containers", nil, nil, nil, &rows); err != nil {
			return row, false, err
		}
		for _, candidate := range rows {
			if candidate.Name == p.Name {
				if found {
					return row, false, errors.New("multiple VMs match the pending name; inspect their IDs")
				}
				row, found = candidate, true
			}
		}
	} else {
		row.ID = p.ID
	}
	if found {
		if _, err := client.doContext(ctx, "GET", pathf("/api/containers/%s", row.ID), nil, nil, nil, &row); err != nil {
			return row, false, err
		}
	} else {
		if p.Submitted {
			return row, false, errors.New("creation was submitted but is not visible yet; no duplicate request was sent. Retry resume later, or check resource lists before explicitly clearing the record")
		}
		if p.Kind == "sandbox" {
			if err := checkCreationWorkspace(ctx, client, p.Workspace, out); err != nil {
				return row, false, err
			}
		}
		variables := map[string]string{managedOwnerEnv(p.Kind): p.Owner}
		body := map[string]any{"name": p.Name, "repo": managedRepo(p.Kind), "tag": p.Tag, "variables": variables}
		if p.Kind == "monitor" {
			body["object_storage"] = map[string]any{}
		} else {
			binding, err := json.Marshal(p.Monitor)
			if err != nil {
				return row, false, err
			}
			variables["SANDBOX_INSTANCE_ID"], variables["MONITOR_BINDING"] = p.Instance, string(binding)
			body["network_policy"] = sandboxNetworkPolicy(p.Monitor.ContainerID)
			if p.Workspace != "" {
				body["volumes"] = map[string]string{"workspace": p.Workspace}
			}
		}
		p.Submitted = true
		if err := writeStorageJSON(path, p, false); err != nil {
			return row, false, err
		}
		fmt.Fprintln(out, "Publishing configuration. This may take several minutes; Ctrl-C keeps the pending creation for resume.")
		if _, err := client.doContext(ctx, "POST", "/api/containers", nil, nil, body, &row); err != nil {
			return row, false, err
		}
	}
	if err := verifyCreationRow(*p, row); err != nil {
		return row, false, err
	}
	if p.ID == "" {
		p.ID = row.ID
		if err := writeStorageJSON(path, p, false); err != nil {
			return row, false, err
		}
	}
	if row.Status != statusRunning && noWait {
		return row, false, creationBootError(row)
	}
	lastProgress := ""
	var err error
	row, err = pollContainerContext(ctx, client, row.ID, row, sandboxBootTimeout, func(current containerView) (bool, error) {
		if err := verifyCreationRow(*p, current); err != nil {
			return false, err
		}
		if err := creationBootError(current); err != nil {
			return false, err
		}
		if line := progressLine(current); line != lastProgress {
			fmt.Fprintln(out, line)
			lastProgress = line
		}
		return current.Status == statusRunning, nil
	})
	if err != nil {
		return row, false, err
	}
	// The create response may omit volumes. Re-read the final measured bindings
	// even if it was already running when returned by POST.
	if _, err := client.doContext(ctx, "GET", pathf("/api/containers/%s", row.ID), nil, nil, nil, &row); err != nil {
		return row, false, err
	}
	if err := verifyCreationRow(*p, row); err != nil {
		return row, false, err
	}
	if row.Status != statusRunning {
		return row, false, fmt.Errorf("%s is now %s; inspect before resuming", row.Name, row.Status)
	}
	if p.Kind == "sandbox" {
		if p.Workspace != "" && row.Volumes["workspace"] != p.Workspace {
			return row, false, errors.New("workspace volume does not match pending creation")
		}
		if err := validateSandboxNetwork(row); err != nil {
			return row, false, err
		}
	}
	return row, true, nil
}

func verifyCreationRow(p pendingCreation, row containerView) error {
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	if !looksLikeUUID(row.ID) || (p.ID != "" && row.ID != p.ID) || row.Name != p.Name || row.Repo != managedRepo(p.Kind) || row.Debug || row.CurrentTag != p.Tag || env[managedOwnerEnv(p.Kind)] != p.Owner {
		return errors.New("resource does not match the saved creation's identity, release or measured owner")
	}
	if p.Kind == "sandbox" {
		var binding monitorBinding
		if json.Unmarshal([]byte(env["MONITOR_BINDING"]), &binding) != nil || binding != *p.Monitor || env["SANDBOX_INSTANCE_ID"] != p.Instance {
			return errors.New("resource does not match the saved sandbox instance and Monitor binding")
		}
	}
	return nil
}

func creationBootError(row containerView) error {
	if err := failureError(row); err != nil {
		return err
	}
	if row.Status == statusStopped || row.Status == statusStopping {
		return fmt.Errorf("%s is %s; inspect it and use start or restart to retry", row.Name, row.Status)
	}
	return nil
}

func managedRepo(kind string) string {
	if kind == "monitor" {
		return monitorRepo
	}
	return defaultSandboxRepo
}

func managedOwnerEnv(kind string) string {
	if kind == "monitor" {
		return monitorOwnerEnv
	}
	return sandboxOwnerEnv
}
