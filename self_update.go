package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/selfupdate"
)

const selfUpdateName = "update"

type selfUpdateRunner interface {
	Run(context.Context, bool) (selfupdate.Result, error)
}

func init() {
	rootCmd.AddCommand(newSelfUpdateCommand(func() selfUpdateRunner {
		return selfupdate.NewUpdater(selfupdate.Options{
			Version: version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			Executable: os.Executable,
		})
	}))
}

func newSelfUpdateCommand(newUpdater func() selfUpdateRunner) *cobra.Command {
	var check bool
	var output string
	cmd := &cobra.Command{
		Use: selfUpdateName, Short: "Update the CLI to the latest stable release",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("unsupported output format %q: use text or json", output)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			result, err := newUpdater().Run(ctx, check)
			if err != nil {
				return err
			}
			if output == "json" {
				err = json.NewEncoder(cmd.OutOrStdout()).Encode(result)
			} else {
				switch result.Status {
				case selfupdate.StatusInstalled:
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated tinfoil from %s to %s.\n", result.Current, result.Latest)
				case selfupdate.StatusAvailable:
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "Update available: %s -> %s. Run: %s\n", result.Current, result.Latest, updateCommand)
				default:
					_, err = fmt.Fprintf(cmd.OutOrStdout(), "tinfoil %s is up to date (latest stable: %s); no downgrade performed.\n", result.Current, result.Latest)
				}
			}
			if err != nil {
				if result.Status == selfupdate.StatusInstalled {
					return fmt.Errorf("tinfoil %s is installed at %s; writing result failed: %w", result.Latest, result.Path, err)
				}
				return fmt.Errorf("no executable was changed; writing result failed: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check fresh release metadata without downloading or changing files")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text or json")
	return cmd
}

func isSelfUpdateCommand(root *cobra.Command, args []string) bool {
	cmd, _, err := root.Find(args)
	return err == nil && cmd.Parent() == root && cmd.Name() == selfUpdateName
}
