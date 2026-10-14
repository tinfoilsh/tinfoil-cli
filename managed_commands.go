package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const managedKindAnnotation = "managed-kind"

func init() {
	start := newManagedContainerCmd("monitor", "start", containerDeployCmd, "no-wait")
	start.Short = "Start a stopped or failed Monitor using its saved configuration"
	monitorCmd.AddCommand(start,
		newManagedContainerCmd("monitor", "stop", containerStopCmd),
		newManagedContainerCmd("monitor", "delete", containerDeleteCmd, "yes"))
	for _, group := range []*cobra.Command{sandboxCmd, monitorCmd} {
		update := newManagedContainerCmd(group.Name(), "update", containerUpdateCmd, "tag", "yes", "no-wait")
		update.Long = "Review and apply a release update, switching traffic automatically. The shared update plan and downtime confirmation still apply, including with --no-wait."
		group.AddCommand(update)
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
