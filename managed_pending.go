package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var managedNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// One account-scoped intent survives publication, lost replies and interrupted
// boot polling. It contains public bindings only; credential custody stays in
// the existing resource/workspace stores.
type pendingCreation struct {
	Version   int             `json:"version"`
	Scope     accountScope    `json:"scope"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Tag       string          `json:"tag"`
	Owner     string          `json:"owner_public_key"`
	Instance  string          `json:"instance_id"`
	Monitor   *monitorBinding `json:"monitor,omitempty"`
	Workspace string          `json:"workspace_volume_id,omitempty"`
	ID        string          `json:"container_id,omitempty"`
	Submitted bool            `json:"submitted"`
}

func pendingCreationPath(scope accountScope) (string, error) {
	config, err := configPath()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(config), "resources", storageHash(data), "pending-creation.json"), nil
}

func validatePendingCreation(p pendingCreation, scope accountScope) error {
	if p.Version != 1 || p.Scope != scope || scope.UserID == "" ||
		(p.Kind != "monitor" && p.Kind != "sandbox") || !managedNamePattern.MatchString(p.Name) ||
		strings.TrimSpace(p.Tag) == "" || !looksLikeUUID(p.Instance) ||
		(p.ID != "" && !looksLikeUUID(p.ID)) {
		return errors.New("invalid pending creation or account scope")
	}
	if _, err := measuredOwner(p.Owner); err != nil {
		return err
	}
	if p.Kind == "sandbox" {
		if p.Monitor == nil || !looksLikeUUID(p.Monitor.ContainerID) {
			return errors.New("invalid pending Monitor binding")
		}
		if _, err := measuredOwner(p.Monitor.Owner); err != nil {
			return err
		}
		if p.Workspace != "" && !looksLikeUUID(p.Workspace) {
			return errors.New("invalid pending workspace UUID")
		}
	} else if p.Monitor != nil || p.Workspace != "" {
		return errors.New("Monitor creation cannot have a workspace or Monitor binding")
	}
	return nil
}

func readPendingCreation(path string, scope accountScope) (pendingCreation, error) {
	var p pendingCreation
	err := readStorageJSON(path, &p)
	if err == nil {
		err = validatePendingCreation(p, scope)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return p, fmt.Errorf("could not read pending creation: %w; check resource lists before using `tinfoil sandbox pending clear` (remote resources are kept)", err)
	}
	return p, err
}

func newManagedPendingCmd(kind string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use: "pending [clear]", Short: "Show or clear this account's unfinished sandbox or Monitor creation",
		ValidArgs: []string{"clear"}, Args: cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, _, err := currentScope()
			if err != nil {
				return err
			}
			path, err := pendingCreationPath(scope)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				p, err := readPendingCreation(path, scope)
				if errors.Is(err, os.ErrNotExist) {
					if outputFormat == "json" {
						return printJSON(nil)
					}
					fmt.Fprintln(cmd.OutOrStdout(), "No pending creation in this account.")
					return nil
				}
				if err != nil {
					return err
				}
				if outputFormat == "json" {
					return printJSON(p)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Pending %s: %s\nRelease: %s\nResource ID: %s\nSubmitted: %t\nResume: tinfoil %s resume\n", p.Kind, p.Name, p.Tag, p.ID, p.Submitted, p.Kind)
				return nil
			}
			unlock, err := acquireStorageLock(path)
			if err != nil {
				return err
			}
			defer unlock()
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(cmd.OutOrStdout(), "No pending creation in this account.")
				return nil
			} else if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Inspect sandbox and Monitor status first. Clearing only forgets this local record; VMs, billable storage, keys and grants are kept.")
			if err := confirmYes(yes, kind+" pending clear"); err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cleared pending creation. Remote resources and saved credentials are kept.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip confirmation when clearing the local record")
	return cmd
}
