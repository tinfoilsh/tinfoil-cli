package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultSandboxRepo   = "tinfoilsh/confidential-agent-sandbox"
	sandboxLoginUser     = "sandbox"
	sandboxOwnerEnv      = "SANDBOX_OWNER_PUBLIC_KEY"
	sandboxDiskKeyName   = "disk.key"
	sandboxSSHKeyName    = "owner_ed25519"
	sandboxBootTimeout   = 10 * time.Minute
	sandboxEnrollTimeout = 2 * time.Minute
	maxEnrollReplyBytes  = 1 << 12
)

// Restrict names used by older credential directories to one path component.
var sandboxNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

type sandboxKeys struct {
	dir             string
	diskKey         []byte
	sshKeyPath      string
	agentKey        string
	monitorIdentity string
}

var sandboxYes bool

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	sandboxCmd.PersistentFlags().StringVar(&attestSSHIdentity, "identity", "", "Owner SSH identity file")
	sandboxCmd.AddCommand(sandboxListCmd, sandboxStartCmd, sandboxRestartCmd, sandboxStopCmd, sandboxDeleteCmd, sandboxEnrollCmd)
	for _, cmd := range []*cobra.Command{sandboxStartCmd, sandboxRestartCmd, sandboxEnrollCmd} {
		addTrustDangerousFlag(cmd)
	}
	sandboxDeleteCmd.Flags().BoolVar(&sandboxYes, "yes", false, "Skip the confirmation prompt")
	silenceUsageRecursive(sandboxCmd)
}

var sandboxCmd = &cobra.Command{
	Use: "sandbox", Aliases: []string{"sandboxes"}, Short: "Manage your confidential sandboxes", SilenceUsage: true,
}

var sandboxListCmd = &cobra.Command{
	Use: "list", Aliases: []string{"ls"}, Short: "List your sandboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var rows []containerView
		if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
			return err
		}
		list := []containerView{}
		for _, row := range rows {
			if row.Repo == defaultSandboxRepo && !row.Debug {
				list = append(list, row)
			}
		}
		return renderContainers(list)
	},
}

var sandboxStartCmd = &cobra.Command{
	Use: "start [id|name]", Short: "Start a stopped sandbox and enroll this machine's keys into it",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("start"),
}
var sandboxRestartCmd = &cobra.Command{
	Use: "restart [id|name]", Short: "Restart a sandbox and enroll this machine's keys into it",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("restart"),
}
var sandboxStopCmd = &cobra.Command{
	Use: "stop [id|name]", Short: "Stop a sandbox, keeping its workspace",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("stop"),
}
var sandboxDeleteCmd = &cobra.Command{
	Use: "delete [id|name]", Short: "Delete a sandbox, keeping its workspace volume",
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("delete"),
}
var sandboxEnrollCmd = &cobra.Command{
	Use: "enroll [id|name]", Short: "Attest, enroll and install the SSH profile for a running sandbox",
	Long: `Verify the current boot and its owner binding, then send the saved
workspace key and Monitor agent identity over attested SSH and install the SSH profile.
Credentials stay local, scoped by account and resource. Existing credential files
are reused. A new sandbox reuses the saved workspace key for its volume in the
same account. Keep the original credentials and owner public key when moving a
workspace. Retry this command after a lost enrollment reply or a reboot.`,
	Args: cobra.ExactArgs(1), RunE: runSandboxAction("enroll"),
}

func runSandboxAction(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		row, err := resolveContainerDetail(client, args[0])
		if action == "delete" && missingContainer(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %s is already deleted. Saved encryption credentials are kept.\n", args[0])
			return nil
		}
		if err != nil {
			return err
		}
		if row.Repo != defaultSandboxRepo || row.Debug {
			return fmt.Errorf("container %s is not a sandbox", row.Name)
		}
		switch action {
		case "delete":
			fmt.Fprintf(cmd.ErrOrStderr(), "Deleting %s keeps its encrypted workspace volume and storage charges until `tinfoil volume delete` removes it. Keep your saved encryption credentials.\n", row.Name)
			if err := confirmYes(sandboxYes, "sandbox delete"); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/containers/%s", row.ID), nil, nil, nil); err != nil && !missingContainer(err) {
				return err
			}
			if err := forgetSandbox(row.Name, row.ID); err != nil {
				return fmt.Errorf("%s is deleted, but %w", row.Name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Saved encryption credentials are kept. Remove any access grants in the Monitor UI.\n", row.Name)
			return nil
		case "stop":
			stopped, err := stopContainer(client, *row)
			if err != nil {
				return err
			}
			return renderContainer(stopped)
		case "start", "restart":
			started, err := startSandboxRow(client, *row, action == "restart")
			if err != nil {
				return err
			}
			row = &started
			if row.Volumes == nil {
				row, err = resolveContainerDetail(client, row.ID)
				if err != nil {
					return err
				}
			}
		}
		target, err := resolveWorkload(*row, defaultSandboxRepo, repo)
		if err != nil {
			return err
		}
		if err := enrollSandbox(target); err != nil {
			return err
		}
		return renderContainer(*row)
	}
}

func startSandboxRow(client *cpClient, row containerView, restart bool) (containerView, error) {
	if row.Repo != defaultSandboxRepo || row.Debug {
		return row, fmt.Errorf("container %s is not a sandbox", row.Name)
	}
	if restart || row.Status == statusStopped || row.Status == statusFailed {
		if err := validateSandboxNetwork(row); err != nil {
			return row, err
		}
		var err error
		if restart && row.Status != statusStopped {
			row, err = stopContainer(client, row)
			if err != nil {
				return row, err
			}
		}
		fmt.Fprintf(os.Stderr, "Booting %s. A cold boot takes a few minutes.\n", row.Name)
		row, err = postContainerAction(client, row.ID, "deploy", nil)
		if err != nil {
			return row, err
		}
	}
	if err := failureError(row); err != nil {
		return row, err
	}
	if row.Status != statusRunning {
		return followContainer(client, row.ID, row)
	}
	return row, nil
}

func enrollSandbox(target *workloadTarget) error {
	s, err := connectSandbox(target)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.enroll(); err != nil {
		return err
	}
	if err := s.install(); err != nil {
		return fmt.Errorf("%s was enrolled, but its ssh profile was not installed: %w; retry `tinfoil sandbox enroll %s`", target.Name, err, target.Name)
	}
	return nil
}

// The fixed endpoint is usable only with an explicit matching alias policy.
func sandboxNetworkMatches(row containerView, monitorID string) bool {
	policy := row.NetworkPolicy
	if policy == nil || policy.Public || policy.EgressMode != "restricted" || len(policy.Egress) != 1 {
		return false
	}
	peer := policy.Egress[0]
	return peer.ContainerID == monitorID && peer.Port == 22 && peer.Alias != nil &&
		*peer.Alias == (containerAlias{IP: "10.254.0.1", Port: 22})
}

func validateSandboxNetwork(row containerView) error {
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	var binding monitorBinding
	if json.Unmarshal([]byte(env["MONITOR_BINDING"]), &binding) != nil || !looksLikeUUID(binding.ContainerID) || binding.Owner == "" {
		return errors.New("sandbox has no measured Monitor binding")
	}
	if !sandboxNetworkMatches(row, binding.ContainerID) {
		return errors.New("sandbox requires a TCP alias matching its measured Monitor binding; update its configuration and network policy")
	}
	return nil
}

func sandboxName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !sandboxNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid sandbox name %q: use letters, digits, dashes or underscores, starting with a letter or digit, up to 63 characters", raw)
	}
	return name, nil
}
