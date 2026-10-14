package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func init() {
	sandboxCmd.AddCommand(sandboxStatusCmd)
	monitorCmd.AddCommand(newManagedStatusCmd("monitor"))
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
				return renderManagedStatus(client, *row, kind, cmd.OutOrStdout())
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			var previous string
			_, err = pollContainerContext(ctx, client, row.ID, *row, 0, func(current containerView) (bool, error) {
				if err := checkManagedKind(kind, current); err != nil {
					return false, err
				}
				snapshot, err := json.Marshal(current)
				if err != nil {
					return false, err
				}
				if string(snapshot) == previous {
					return false, nil
				}
				previous = string(snapshot)
				return false, renderManagedStatus(client, current, kind, cmd.OutOrStdout())
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

func renderManagedStatus(client *cpClient, row containerView, kind string, out io.Writer) error {
	if err := renderContainer(row); err != nil || outputFormat == "json" {
		return err
	}
	fmt.Fprintln(out, managedStateDescription(row.Status))
	if kind == "sandbox" {
		env, err := measuredEnvironment(row.Config)
		binding, bindingErr := sandboxMonitorBinding(env)
		if err != nil || bindingErr != nil {
			fmt.Fprintln(out, "Monitor: measured binding unavailable; inspect the configuration after publication finishes.")
		} else if monitor, err := managedRow(client, "monitor", binding.ContainerID); missingContainer(err) {
			fmt.Fprintln(out, "Monitor: unavailable; check whether it was deleted or is in another account.")
		} else if err != nil {
			return err
		} else {
			fmt.Fprintf(out, "Monitor: %s (%s)\n", monitor.Name, statusLabel(monitor.Status))
			if monitor.Status != statusRunning {
				fmt.Fprintln(out, "Service access waits until Monitor is running and unlocked.")
			}
		}
		fmt.Fprintf(out, "Connect: tinfoil attest-ssh %s --install && ssh %s\nRerun after either VM reboots to attest and unlock access.\n", row.Name, row.Name)
	} else {
		fmt.Fprintf(out, "Open: tinfoil monitor open %s\nKeep that command running while using its local Monitor panel URL.\n", row.Name)
	}
	if message := containerFailureMessage(row); message != "" {
		if hint := managedDeploymentHint(message); hint != "" {
			fmt.Fprintln(out, hint)
		}
	}
	return nil
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

func managedStateDescription(state string) string {
	switch state {
	case statusCreated:
		return "The name is reserved while configuration publication finishes; this can take several minutes."
	case statusPending:
		return "Waiting for deployment to begin."
	case statusDeploying:
		return "The VM is being provisioned."
	case statusStarted:
		return "The VM is booting and waiting for its workload."
	case statusRunning:
		return "The VM is running. Connect from this computer to verify and unlock it."
	case statusStopping:
		return "Waiting for shutdown; the host allows up to five minutes for graceful shutdown."
	case statusStopped:
		return "Start this VM to connect again. Stored data is retained."
	case statusFailed:
		return "Check the deployment error and boot details before restarting."
	default:
		return "Status unavailable. Refresh before taking an action."
	}
}

func managedDeploymentHint(message string) string {
	switch {
	case strings.Contains(message, "no approved config registry revision"):
		return "Configuration approval is pending. Wait for publication before retrying Start or Restart; if it persists, contact support with the configuration path above."
	case strings.Contains(message, "approval has expired"):
		return "Configuration approval expired. Wait for renewal before retrying Start or Restart."
	case strings.Contains(message, "waiting for worker handoff"):
		return "Configuration publication is temporarily unavailable during a service update. Wait, then retry Start or Restart."
	default:
		return ""
	}
}
