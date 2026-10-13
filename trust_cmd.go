package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// tinfoil trust — inspect and configure the known-configs trust store from
// the CLI, so changing mode/record or finding the file to edit does not
// require remembering its path.
var (
	trustSetMode   string
	trustSetRecord string
	trustSetPrune  bool
)

func init() {
	rootCmd.AddCommand(trustCmd)
	trustCmd.AddCommand(trustSetCmd)
	trustSetCmd.Flags().StringVar(&trustSetMode, "mode", "", "prompt (unknown configs ask) or frozen (unknown configs fail)")
	trustSetCmd.Flags().StringVar(&trustSetRecord, "record", "", "what a yes records: org, project, or pin")
	trustSetCmd.Flags().BoolVar(&trustSetPrune, "prune", false, "when tightening the record granularity, also remove the broader allow entries so it is the only pass")
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Show the known-configs trust store",
	Long: `Show which configs this machine trusts for container connections, the
store's mode and record granularity, and where the file lives (it is yours to edit).

  tinfoil trust
  tinfoil trust set --mode frozen
  tinfoil trust set --record pin`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := loadConnectionPolicy()
		if err != nil {
			return err
		}
		printTrustStore(cmd.OutOrStdout(), policy)
		return nil
	},
}

var trustSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the trust store's mode and/or record granularity",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if trustSetMode == "" && trustSetRecord == "" {
			return fmt.Errorf("nothing to set: pass --mode and/or --record")
		}
		policy, err := loadConnectionPolicy()
		if err != nil {
			// A malformed store must be fixed by hand, not overwritten.
			return err
		}
		if err := policy.setDefaults(trustSetMode, trustSetRecord); err != nil {
			return err
		}
		if err := offerPrune(cmd, &policy); err != nil {
			return err
		}
		printTrustStore(cmd.OutOrStdout(), policy)
		return nil
	},
}

// offerPrune makes tightening one deliberate step: when the new level leaves
// broader allow entries in force, remove them with --prune, or offer to on a
// TTY. Declining (or no TTY) keeps them; the store printout's note says what
// that means.
func offerPrune(cmd *cobra.Command, policy *connectionPolicy) error {
	broader := policy.broaderThan(policy.Record)
	if trustSetRecord == "" || len(broader) == 0 {
		return nil
	}
	out := cmd.OutOrStdout()
	prune := trustSetPrune
	if !prune && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(out, "Record is now set to: %s. %d broader entr%s still grant%s more:\n", policy.Record, len(broader), plural(len(broader), "y", "ies"), plural(len(broader), "s", ""))
		for _, entry := range broader {
			fmt.Fprintf(out, "  %s\n", entry)
		}
		fmt.Fprintf(out, "Remove them so %s is the only pass? [y/N] ", policy.Record)
		scanner := bufio.NewScanner(cmd.InOrStdin())
		if scanner.Scan() {
			answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
			prune = answer == "y" || answer == "yes"
		} else {
			fmt.Fprintln(out)
		}
	}
	if !prune {
		return nil
	}
	// Reload before pruning: a connect in another terminal may have
	// journaled a pin while the prompt waited, and pruning from the stale
	// store would drop it.
	fresh, err := loadConnectionPolicyFrom(policy.path)
	if err != nil {
		return fmt.Errorf("re-reading %s before pruning: %w", policy.path, err)
	}
	if err := fresh.pruneBroaderThan(fresh.Record); err != nil {
		return err
	}
	*policy = fresh
	fmt.Fprintf(out, "Removed %d broader entr%s.\n", len(broader), plural(len(broader), "y", "ies"))
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func printTrustStore(out io.Writer, policy connectionPolicy) {
	fmt.Fprintf(out, "Store: %s", policy.path)
	if _, err := os.Stat(policy.path); os.IsNotExist(err) {
		fmt.Fprint(out, " (not created yet)")
	}
	fmt.Fprintf(out, "\nMode:  %s", policy.Mode)
	switch policy.Mode {
	case policyModePrompt:
		fmt.Fprint(out, "  (unknown configs ask first)")
	case policyModeFrozen:
		fmt.Fprint(out, "  (unknown configs fail; the file changes only by hand)")
	}
	fmt.Fprintf(out, "\nRecord: %s  (what a yes records)\n", policy.Record)
	section := func(name string, entries []string, limit int) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(out, "\n  %s:\n", name)
		shown := entries
		if limit > 0 && len(entries) > limit {
			shown = entries[:limit]
		}
		for _, entry := range shown {
			fmt.Fprintf(out, "    %s\n", entry)
		}
		if rest := len(entries) - len(shown); rest > 0 {
			fmt.Fprintf(out, "    … %d more (see the file)\n", rest)
		}
	}
	if len(policy.Allow.Orgs)+len(policy.Allow.Projects)+len(policy.Allow.Pins) == 0 {
		if policy.Mode == policyModeFrozen {
			fmt.Fprint(out, "\nNothing trusted yet: mode frozen refuses unknown configs — add entries to the file by hand, or connect with an explicit --repo.\n")
		} else {
			fmt.Fprint(out, "\nNothing trusted yet: the first interactive connect will prompt; scripts must state an expectation with --repo.\n")
		}
	} else {
		fmt.Fprint(out, "\nTrusted:\n")
		section("Orgs (any project)", policy.Allow.Orgs, 0)
		section("Projects (any config)", policy.Allow.Projects, 0)
		section("Pinned configs", policy.Allow.Pins, pinDisplayLimit)
	}
	if broader := policy.broaderThan(policy.Record); len(broader) > 0 {
		// Record controls what a yes records, never how existing entries
		// match — after tightening, surviving broad lines are the loophole.
		fmt.Fprintf(out, "\nNote: record is set to %s.\n%d broader entr%s above still grant%s more access. Prune with: tinfoil trust set --record %s --prune\n", policy.Record, len(broader), plural(len(broader), "y", "ies"), plural(len(broader), "s", ""), policy.Record)
	}
}

// pinDisplayLimit keeps `tinfoil trust` readable once the journal grows; the
// file has the full list.
const pinDisplayLimit = 5
