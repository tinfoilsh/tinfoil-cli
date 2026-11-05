package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"golang.org/x/term"
)

type containerNetworkPolicy = controlplane.NetworkPolicy
type containerPeer = controlplane.Peer
type containerAlias = controlplane.Alias
type containerView = controlplane.Container
type candidateConfig = controlplane.CandidateConfig
type bootStage = controlplane.BootStage
type bootStages = controlplane.BootStages

type hostInfo struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	IsDefault          bool   `json:"is_default"`
	AvailableGpuValues []int  `json:"available_gpu_values"`
}

const (
	containerSourceGitHub   = "github"
	containerSourceRegistry = "registry"
	containerSourceLocal    = "local"
)

func newContainerCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, outputOpts *outputOptions, rootOpts *rootOptions) *cobra.Command {
	containerCmd := &cobra.Command{
		Use:     "container",
		Aliases: []string{"containers", "ct"},
		Short:   "Manage Tinfoil containers",
	}
	containerCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	containerCmd.AddCommand(newContainerListCommand(newClient, outputOpts))
	containerCmd.AddCommand(newContainerGetCommand(newClient, outputOpts))
	containerCmd.AddCommand(newContainerCreateCommand(pollingOpts, newClient, &containerCreateOptions{}, outputOpts, rootOpts, &waitOptions{}))
	containerCmd.AddCommand(newContainerDeleteCommand(newClient, &containerDeleteOptions{}))
	containerCmd.AddCommand(newContainerDeployCommand(pollingOpts, newClient, &containerDeployOptions{}, outputOpts, &waitOptions{}))
	containerCmd.AddCommand(newContainerStopCommand(newClient, outputOpts))
	containerCmd.AddCommand(newContainerUpdateCommand(pollingOpts, newClient, &containerUpdateOptions{}, outputOpts, &waitOptions{}))
	containerCmd.AddCommand(newContainerPromoteCommand(pollingOpts, newClient, outputOpts, &waitOptions{}))
	containerCmd.AddCommand(newContainerCancelCommand(newClient, &containerCancelOptions{}))
	containerCmd.AddCommand(newContainerMetricsCommand(newClient, &containerMetricsOptions{}))
	containerCmd.AddCommand(newContainerHostsCommand(newClient, outputOpts))
	containerCmd.AddCommand(newContainerConnectCommand(newClient, &containerConnectOptions{}, &proxyOptions{}, rootOpts, &trustOptions{}))
	return containerCmd
}

func newContainerListCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	containerListCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List containers in the current organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			return listContainers(commandStreams(cmd), outputOpts, client, "")
		},
	}

	return containerListCmd
}

func listContainers(streams commandIO, outputOpts *outputOptions, client *cpClient, kind string) error {
	var rows []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
		return err
	}
	list := []containerView{}
	for _, row := range rows {
		if checkManagedKind(kind, row) == nil {
			list = append(list, row)
		}
	}
	return renderContainers(streams, outputOpts, list)
}

func newContainerGetCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	containerGetCmd := &cobra.Command{
		Use:   "get [id|name]",
		Short: "Show a single container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainerDetail(client, args[0])
			if err != nil {
				return err
			}
			attached, err := loadContainerVolumes(client, *c)
			if err != nil {
				return err
			}
			return renderContainerDetail(commandStreams(cmd), outputOpts, *c, attached)
		},
	}

	return containerGetCmd
}

func newContainerCreateCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, containerCreateOpts *containerCreateOptions, outputOpts *outputOptions, rootOpts *rootOptions, waitOpts *waitOptions) *cobra.Command {
	containerCreateCmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new container",
		Long:  "With --config, keep the file: later connections are verified against it.",
		Example: `  From a GitHub release
  tinfoil container create app --repo org/repo --tag v1.2.3

  From a registry config
  tinfoil container create app --source registry --repo org/project --revision v1.2.3

  From a local config file
  tinfoil container create app --config tinfoil-config.yml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rootOpts.localConfigFile != "" {
				if cmd.Flags().Changed("source") && containerCreateOpts.createSource != containerSourceLocal {
					return fmt.Errorf("--config requires --source local")
				}
				containerCreateOpts.createSource = containerSourceLocal
			}
			if containerCreateOpts.createSource != containerSourceGitHub && containerCreateOpts.createSource != containerSourceRegistry && containerCreateOpts.createSource != containerSourceLocal {
				return fmt.Errorf("--source must be github, registry, or local")
			}
			if containerCreateOpts.createSource == containerSourceRegistry && containerCreateOpts.createTag != "" {
				return fmt.Errorf("use --revision instead of --tag for registry configs")
			}
			if containerCreateOpts.createSource != containerSourceGitHub && containerCreateOpts.createReplaceID != "" {
				return fmt.Errorf("%s configs do not support --replace; create a new container before removing the old one", containerCreateOpts.createSource)
			}
			revision := containerCreateOpts.createRevision
			if revision == "" {
				revision = containerCreateOpts.createTag
			}
			body := map[string]any{"name": args[0]}
			if containerCreateOpts.createSource == containerSourceLocal {
				if containerCreateOpts.createRepo != "" || revision != "" {
					return fmt.Errorf("local configs cannot use --repo, --tag, or --revision")
				}
				data, err := readLocalConfig(rootOpts)
				if err != nil {
					return err
				}
				body["source"], body["config"] = containerSourceLocal, data
			} else {
				if containerCreateOpts.createRepo == "" {
					return fmt.Errorf("--repo is required for %s configs", containerCreateOpts.createSource)
				}
				body["repo"] = containerCreateOpts.createRepo
				if containerCreateOpts.createSource == containerSourceRegistry {
					body["source"] = containerCreateOpts.createSource
				}
				if containerCreateOpts.createRevision != "" {
					body["revision"] = revision
				} else {
					body["tag"] = revision
				}
			}
			if err := setMarkLatestRelease(cmd, body, containerCreateOpts.createMarkLatestRelease); err != nil {
				return err
			}
			secrets, err := parseSecretSelection(containerCreateOpts.createSecrets)
			if err != nil {
				return err
			}

			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}

			vars, err := parseKeyValues(containerCreateOpts.createVariables)
			if err != nil {
				return err
			}

			if containerCreateOpts.createSource == containerSourceGitHub && containerCreateOpts.createRepo == defaultSandboxRepo {
				if containerCreateOpts.createDebug || containerCreateOpts.createDisableCC {
					return fmt.Errorf("sandbox aliases require a production deployment")
				}
				if vars["NO_MONITOR"] != "1" {
					return fmt.Errorf("use `tinfoil sandbox create NAME --monitor MONITOR --tag VERSION` to create a monitored sandbox")
				}
			}

			if containerCreateOpts.createDisableCC {
				if err := confirmNonCCMode(commandStreams(cmd), containerCreateOpts); err != nil {
					return err
				}
			}

			requests, err := parseVolumeRequests(containerCreateOpts.createVolumes)
			if err != nil {
				return err
			}
			var replacement *containerView
			replaceID := strings.TrimSpace(containerCreateOpts.createReplaceID)
			if replaceID != "" {
				if !looksLikeUUID(replaceID) {
					return fmt.Errorf("--replace requires a container ID")
				}
				replacement, err = resolveContainerDetail(client, replaceID)
				if err != nil {
					return fmt.Errorf("resolve --replace target: %w", err)
				}
				if !strings.EqualFold(replacement.ID, replaceID) {
					return fmt.Errorf("resolve --replace target: unexpected container ID; refusing to replace")
				}
				replaceID = replacement.ID
			}
			// A slot with a key secret cannot run without a disk, so refuse up front
			// with the commands to run rather than creating a container that sits
			// stopped. Slots without one are optional and the container deploys
			// with them empty.
			if containerCreateOpts.createSource == containerSourceGitHub {
				slots, err := declaredVolumeSlots(client, containerCreateOpts.createRepo, revision, args[0], replaceID)
				if err != nil {
					return err
				}
				planned := containerView{Name: args[0], VolumeSlots: slots}
				assignments, err := volumeAssignments(&planned, requests)
				if err != nil {
					return err
				}
				assigned := map[string]bool{}
				for _, name := range assignments {
					assigned[name] = true
				}
				var missing []volumeSlot
				for _, mount := range requiredVolumeSlots(slots) {
					if !assigned[mount.Name] {
						missing = append(missing, mount)
					}
				}
				if len(missing) > 0 {
					return errVolumesRequired(args[0], missing, containerCreateOpts.createHost)
				}
			}
			var volumes []volumeView
			if len(requests) > 0 {
				list, err := listVolumes(client)
				if err != nil {
					return err
				}
				if volumes, err = resolveVolumeRequests(list.Volumes, requests, replacement); err != nil {
					return err
				}
				host, err := volumesHost(volumes, containerCreateOpts.createHost)
				if err != nil {
					return err
				}
				body["host_name"] = host
			}

			if cmd.Flags().Changed("display-order") {
				body["display_order"] = containerCreateOpts.createDisplayOrder
			}
			if len(vars) > 0 {
				body["variables"] = vars
			}
			if len(containerCreateOpts.createSecrets) > 0 {
				body["secrets"] = secrets
			}
			if len(containerCreateOpts.createSSHKeys) > 0 {
				body["ssh_keys"] = containerCreateOpts.createSSHKeys
			}
			if containerCreateOpts.createDebug {
				body["debug"] = true
			}
			if containerCreateOpts.createDisableCC {
				body["disable_cc_mode"] = true
			}
			if containerCreateOpts.createCustomDomain != "" {
				body["custom_domain"] = containerCreateOpts.createCustomDomain
			}
			if containerCreateOpts.createHost != "" && len(requests) == 0 {
				body["host_name"] = containerCreateOpts.createHost
			}
			if replaceID != "" {
				body["replace_container_id"] = replaceID
			}

			var created containerView
			if _, err := client.do("POST", "/api/containers", nil, body, &created); err != nil {
				return err
			}
			// The caller just told us exactly what they intend to run: seed the
			// trust store now so the first connect needs no prompt.
			seedTrustFromCreate(commandStreams(cmd), containerCreateOpts.createRepo, revision)
			deployBody := map[string]any{}
			if value, ok := body["mark_latest_release"].(bool); ok {
				deployBody["mark_latest_release"] = value
				created.MarkLatestRelease = &value
			}
			if len(created.VolumeSlots) == 0 {
				if len(requests) > 0 {
					return createFollowupError(created, replaceID, fmt.Errorf("the returned configuration declares no mounts; --volume was not applied"))
				}
				return createFollowupError(created, replaceID, followAndRender(pollingOpts, commandStreams(cmd), outputOpts, waitOpts, client, created, nil))
			}
			if len(requests) > 0 {
				if err := attachVolumes(client, &created, requests, volumes); err != nil {
					return createFollowupError(created, replaceID, err)
				}
			}
			// The controlplane leaves any volume-declaring container stopped after
			// create; deploy it now so optional slots do not strand it.
			var deployed containerView
			if _, err := client.do("POST", pathf("/api/containers/%s/deploy", created.ID), nil, deployBody, &deployed); err != nil {
				return createFollowupError(created, replaceID, fmt.Errorf("deploy request failed: %w. Check its state before retrying: %s", withAttachHint(err, &created), deployRecoveryCommand(&created)))
			}
			attached, err := loadContainerVolumes(client, deployed)
			if err != nil {
				return createFollowupError(created, replaceID, fmt.Errorf("deploy was accepted (status %s), but could not load attached volumes: %w", deployed.Status, err))
			}
			return createFollowupError(created, replaceID, followAndRender(pollingOpts, commandStreams(cmd), outputOpts, waitOpts, client, deployed, attached))
		},
	}
	containerCreateCmd.Flags().BoolVar(&waitOpts.noWait, "no-wait", false, "Return once the request is accepted")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createRepo, "repo", "", "GitHub repository or registry project (org/project)")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createTag, "tag", "", "GitHub release tag (alias for --revision with --source github)")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createSource, "source", containerSourceGitHub, "Config source: github, registry, or local (implied by --config)")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createRevision, "revision", "", "GitHub release tag, or registry version or sha256:<config digest>")
	containerCreateCmd.Flags().BoolVar(&containerCreateOpts.createDebug, "debug", false, "Enable debug mode (allows SSH into the enclave)")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createMarkLatestRelease, "mark-latest", "", "Mark the tag as the repo's latest GitHub release once running (default true)")
	containerCreateCmd.Flags().BoolVar(&containerCreateOpts.createDisableCC, "disable-cc-mode", false, "EXPERIMENTAL: disable confidential computing (benchmarks only; requires org entitlement)")
	containerCreateCmd.Flags().BoolVar(&containerCreateOpts.createYes, "yes", false, "Skip interactive confirmation for --disable-cc-mode")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createCustomDomain, "custom-domain", "", "Verified custom domain to expose the container on")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createHost, "host", "", "Target host name (see 'tinfoil container hosts')")
	containerCreateCmd.Flags().StringVar(&containerCreateOpts.createReplaceID, "replace", "", "ID of the existing container to replace; its disks may be reused with --volume")
	containerCreateCmd.Flags().StringArrayVar(&containerCreateOpts.createVariables, "variable", nil, "Environment variable in KEY=VALUE form; may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&containerCreateOpts.createSecrets, "secret", nil, "Tinfoil-managed secret name; may be repeated (use --secret=\"\" for none)")
	containerCreateCmd.Flags().StringArrayVar(&containerCreateOpts.createSSHKeys, "ssh-key", nil, "Org SSH key name (debug only); may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&containerCreateOpts.createVolumes, "volume", nil, "Volume to attach before the first deploy, as <id|name>[:<mount name>]; may be repeated")
	containerCreateCmd.Flags().Int32Var(&containerCreateOpts.createDisplayOrder, "display-order", 0, "Sort order of this instance within its project")
	return containerCreateCmd
}

func createFollowupError(created containerView, replaceID string, err error) error {
	if err == nil {
		return nil
	}
	replaced := ""
	if replaceID != "" {
		replaced = fmt.Sprintf("; replaced container %s was removed", replaceID)
	}
	return fmt.Errorf("created %s (%s)%s, but follow-up failed: %w. The new container and any successful disk attachments were retained; inspect with: tinfoil container get %s", created.Name, created.ID, replaced, err, created.ID)
}

func newContainerDeleteCommand(newClient authenticatedClientFactory, containerDeleteOpts *containerDeleteOptions) *cobra.Command {
	containerDeleteCmd := &cobra.Command{
		Use:     "delete [id|name]",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a container",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainerDetail(client, args[0])
			if err != nil {
				return err
			}
			if err := refuseStandaloneMonitor(*c, "delete"); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).err, "Deleting %s (%s).\n", c.Name, c.ID)
			volumes := "Attached volumes are kept."
			if c.Repo == defaultSandboxRepo {
				volumes = "It has no attached workspace volume."
				if c.Volumes[sandboxWorkspaceSlot] != "" {
					volumes = "Its workspace volume and all of its data are deleted too."
				}
			}
			fmt.Fprintln(commandStreams(cmd).err, "This removes the container, its saved configuration, and its DNS records. "+volumes)
			if err := confirmYes(commandStreams(cmd), containerDeleteOpts.deleteYes, cmd.CommandPath()); err != nil {
				return err
			}
			if _, err := client.do("DELETE", pathf("/api/containers/%s", c.ID), nil, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Deleted container %s (%s)\n", c.Name, c.ID)
			return nil
		},
	}
	containerDeleteCmd.Flags().BoolVar(&containerDeleteOpts.deleteYes, "yes", false, "Skip interactive confirmation")
	return containerDeleteCmd
}

func newContainerDeployCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, containerDeployOpts *containerDeployOptions, outputOpts *outputOptions, waitOpts *waitOptions) *cobra.Command {
	containerDeployCmd := &cobra.Command{
		Use:   "deploy [id|name]",
		Short: "Deploy a stopped or failed container",
		Long: `Without flags the saved configuration is used; flags replace parts of it.
To change a running container, use "tinfoil container update".`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainerDeploy(pollingOpts, newClient, containerDeployOpts, outputOpts, waitOpts, cmd, args)
		},
	}
	containerDeployCmd.Flags().BoolVar(&waitOpts.noWait, "no-wait", false, "Return once the request is accepted")
	containerDeployCmd.Flags().StringVar(&containerDeployOpts.deployTag, "tag", "", "Deploy a different release tag than the saved one")
	containerDeployCmd.Flags().StringArrayVar(&containerDeployOpts.deployVariables, "variable", nil, "Replace the saved environment variables with KEY=VALUE pairs; may be repeated")
	containerDeployCmd.Flags().StringArrayVar(&containerDeployOpts.deploySecrets, "secret", nil, "Replace the saved Tinfoil-managed secrets list (specify all; --secret=\"\" clears it)")
	containerDeployCmd.Flags().StringArrayVar(&containerDeployOpts.deploySSHKeys, "ssh-key", nil, "Replace the saved SSH keys list")
	containerDeployCmd.Flags().StringVar(&containerDeployOpts.deployDebug, "debug", "", "Deploy in debug mode (true/false)")
	containerDeployCmd.Flags().StringVar(&containerDeployOpts.deployMarkLatestRelease, "mark-latest", "", "Mark the tag as the repo's latest GitHub release once running (default true)")
	containerDeployCmd.Flags().StringVar(&containerDeployOpts.deployCustomDomain, "custom-domain", "", "Replace the custom domain (empty string clears it)")
	containerDeployCmd.Flags().StringVar(&containerDeployOpts.deployHost, "host", "", "Deploy on a different host (see 'tinfoil container hosts')")
	containerDeployCmd.Flags().StringArrayVar(&containerDeployOpts.deployVolumes, "volume", nil, "Volume to attach before deploying, as <id|name>[:<mount name>]; may be repeated")
	return containerDeployCmd
}

func newContainerStopCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	containerStopCmd := &cobra.Command{
		Use:   "stop [id|name]",
		Short: "Stop a running container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainer(client, args[0])
			if err != nil {
				return err
			}
			if err := refuseStandaloneMonitor(*c, "stop"); err != nil {
				return err
			}
			stopped, err := postContainerAction(client, c.ID, "stop", nil)
			if err != nil {
				return err
			}
			if outputOpts.outputFormat != "json" {
				fmt.Fprintf(commandStreams(cmd).out, "Stopping %s. Its configuration and volumes are kept; run \"tinfoil container deploy %s\" to bring it back.\n", c.Name, c.Name)
			}
			return renderContainer(commandStreams(cmd), outputOpts, stopped)
		},
	}

	return containerStopCmd
}

func newContainerUpdateCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, containerUpdateOpts *containerUpdateOptions, outputOpts *outputOptions, waitOpts *waitOptions) *cobra.Command {
	containerUpdateCmd := &cobra.Command{
		Use:   "update [id|name]",
		Short: "Update a running container to a new tag or configuration",
		Long: `Multi-GPU containers and those with persistent volumes stop first, so their
update has downtime.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainerUpdate(pollingOpts, newClient, containerUpdateOpts, outputOpts, waitOpts, cmd, args)
		},
	}
	containerUpdateCmd.Flags().BoolVar(&waitOpts.noWait, "no-wait", false, "Return once the request is accepted")
	containerUpdateCmd.Flags().StringVar(&containerUpdateOpts.updateTag, "tag", "", "Release tag to update to")
	containerUpdateCmd.Flags().StringArrayVar(&containerUpdateOpts.updateVariables, "variable", nil, "Replace the saved environment variables with KEY=VALUE pairs; may be repeated")
	containerUpdateCmd.Flags().StringArrayVar(&containerUpdateOpts.updateSecrets, "secret", nil, "Replace the saved Tinfoil-managed secrets list (specify all; --secret=\"\" clears it)")
	containerUpdateCmd.Flags().StringArrayVar(&containerUpdateOpts.updateSSHKeys, "ssh-key", nil, "Replace the saved SSH keys list")
	containerUpdateCmd.Flags().StringVar(&containerUpdateOpts.updateDebug, "debug", "", "Switch debug mode on or off (true/false)")
	containerUpdateCmd.Flags().StringVar(&containerUpdateOpts.updateHold, "hold", "", "Hold the new version for review (default: the project's setting)")
	containerUpdateCmd.Flags().Lookup("hold").NoOptDefVal = "true"
	containerUpdateCmd.Flags().StringVar(&containerUpdateOpts.updateMarkLatestRelease, "mark-latest", "", "Mark the tag as the repo's latest GitHub release once running (default true)")
	containerUpdateCmd.Flags().StringVar(&containerUpdateOpts.updateCustomDomain, "custom-domain", "", "Replace the custom domain (empty string clears it)")
	containerUpdateCmd.Flags().BoolVar(&containerUpdateOpts.updateYes, "yes", false, "Approve the update plan, including any downtime")
	return containerUpdateCmd
}

func newContainerMetricsCommand(newClient authenticatedClientFactory, containerMetricsOpts *containerMetricsOptions) *cobra.Command {
	containerMetricsCmd := &cobra.Command{
		Use:   "metrics [id|name]",
		Short: "Show container resource metrics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContainerMetrics(newClient, containerMetricsOpts, cmd, args)
		},
	}
	containerMetricsCmd.Flags().StringVar(&containerMetricsOpts.metricsTime, "time", "24h", "Time window (e.g. 1h, 24h, 7d)")
	return containerMetricsCmd
}

func newContainerHostsCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	containerHostsCmd := &cobra.Command{
		Use:   "hosts",
		Short: "List container hosts available to your organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			var hosts []hostInfo
			if _, err := client.do("GET", "/api/containers/hosts", nil, nil, &hosts); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), hosts)
			}
			if len(hosts) == 0 {
				fmt.Fprintln(commandStreams(cmd).out, "No container hosts available.")
				return nil
			}
			fmt.Fprintf(commandStreams(cmd).out, "%-24s  %-10s  %s\n", "NAME", "DEFAULT", "GPU SIZES")
			for _, h := range hosts {
				fmt.Fprintf(commandStreams(cmd).out, "%-24s  %-10v  %s\n", h.Name, h.IsDefault, formatInts(h.AvailableGpuValues))
			}
			return nil
		},
	}

	return containerHostsCmd
}

func newContainerPromoteCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, outputOpts *outputOptions, waitOpts *waitOptions) *cobra.Command {
	containerPromoteCmd := &cobra.Command{
		Use:   "promote [id|name]",
		Short: "Switch traffic to an update that was held for review",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainer(client, args[0])
			if err != nil {
				return err
			}
			var promoted containerView
			if _, err := client.do("POST", pathf("/api/containers/%s/update/promote", c.ID), nil, nil, &promoted); err != nil {
				return err
			}
			if outputOpts.outputFormat != "json" {
				fmt.Fprintf(commandStreams(cmd).out, "Promoted update on %s; traffic is switching to %s.\n", c.Name, promoted.CurrentTag)
			}
			return followAndRender(pollingOpts, commandStreams(cmd), outputOpts, waitOpts, client, promoted, nil)
		},
	}
	containerPromoteCmd.Flags().BoolVar(&waitOpts.noWait, "no-wait", false, "Return once the request is accepted")
	return containerPromoteCmd
}

func newContainerCancelCommand(newClient authenticatedClientFactory, containerCancelOpts *containerCancelOptions) *cobra.Command {
	containerCancelCmd := &cobra.Command{
		Use:   "cancel [id|name]",
		Short: "Cancel an update and keep the current version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainer(client, args[0])
			if err != nil {
				return err
			}
			var body any
			var response any
			var acknowledgment struct {
				RollbackLatest bool   `json:"rollback_latest"`
				Tag            string `json:"tag"`
			}
			if containerCancelOpts.cancelRollbackLatest {
				body = map[string]bool{"rollback_latest": true}
				response = &acknowledgment
			}
			status, err := client.do("POST", pathf("/api/containers/%s/update/cancel", c.ID), nil, body, response)
			if err != nil {
				if containerCancelOpts.cancelRollbackLatest && status == http.StatusOK {
					return fmt.Errorf("update cancellation may have completed, but the controlplane did not confirm latest release restoration: %w", err)
				}
				return err
			}
			if containerCancelOpts.cancelRollbackLatest {
				if status != http.StatusOK || !acknowledgment.RollbackLatest || strings.TrimSpace(acknowledgment.Tag) == "" {
					return fmt.Errorf("update cancellation may have completed, but the controlplane did not confirm latest release restoration (HTTP %d)", status)
				}
				fmt.Fprintf(commandStreams(cmd).out, "Canceled in-progress update on %s; latest release restoration to %s requested\n", c.Name, acknowledgment.Tag)
				return nil
			}
			fmt.Fprintf(commandStreams(cmd).out, "Canceled update on %s; %s keeps running.\n", c.Name, c.CurrentTag)
			return nil
		},
	}
	containerCancelCmd.Flags().BoolVar(&containerCancelOpts.cancelRollbackLatest, "rollback-latest", false, "Request restoring the repository's latest release to the current production tag")
	return containerCancelCmd
}

func newContainerConnectCommand(newClient authenticatedClientFactory, containerConnectOpts *containerConnectOptions, proxyOpts *proxyOptions, rootOpts *rootOptions, trustOpts *trustOptions) *cobra.Command {
	containerConnectCmd := &cobra.Command{
		Use:   "connect [id|name]",
		Short: "Run a verified proxy to a deployed container",
		Example: `  Proxy to a container
  tinfoil container connect my-container

  Proxy to the update held for review
  tinfoil container connect my-container --review

  Verify against a local config file
  tinfoil container connect my-container --config tinfoil-config.yml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainerDetail(client, args[0])
			if err != nil {
				return err
			}
			sourceOverride := rootOpts.repo
			if rootOpts.repo != "" && !strings.Contains(rootOpts.repo, "/") {
				// A bare org is a valid assertion here but not a verifier pin:
				// tinfoil-go's reference grammar requires owner/name — it has no
				// org-prefix match, even though the endorsed name it compares
				// against would support one. Until the SDK grows that,
				// assertTrustedSource checks the org against the resolved name
				// (which the verifier then proves via the signed name→digest
				// endorsement, backstopping the string check), and the verifier
				// pins the resolved reference.
				sourceOverride = ""
			}
			target, err := containerConnection(*c, containerConnectOpts.connectReview, sourceOverride)
			if err != nil {
				return err
			}
			expected := target.source
			if c.Source == containerSourceLocal {
				// A local config is a caller-held expectation: the file's digest is
				// the trust decision, so the connection policy does not apply.
				if err := checkLocalConfigDigest(rootOpts, target.ConfigDigest); err != nil {
					return err
				}
				expected = "sha256:" + target.ConfigDigest
			} else if rootOpts.repo == "" {
				// The expectation came from the controlplane response, not the
				// caller: check it against the connection policy before trusting it.
				if err := enforceConnectionPolicy(commandStreams(cmd), trustOpts, target.source); err != nil {
					return err
				}
			} else if err := assertTrustedSource(commandStreams(cmd), rootOpts.repo, target.source); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Connecting verified proxy to %s: %s (expected %s)\n", c.Name, target.URL, expected)

			connection := *rootOpts
			connection.enclaveHost, connection.repo = target.host, target.source
			proxy := *proxyOpts
			proxy.listenAddr, proxy.listenPort = containerConnectOpts.connectBindAddr, containerConnectOpts.connectPort
			return runProxy(&proxy, &connection, cmd, nil)
		},
	}
	containerConnectCmd.Flags().UintVarP(&containerConnectOpts.connectPort, "port", "p", 8080, "Local port for the verified proxy")
	containerConnectCmd.Flags().StringVarP(&containerConnectOpts.connectBindAddr, "bind", "b", "127.0.0.1", "Address to bind to")
	containerConnectCmd.Flags().BoolVar(&containerConnectOpts.connectReview, "review", false, "Connect to the update held for review instead of production")
	addTrustDangerousFlag(trustOpts, containerConnectCmd)
	return containerConnectCmd
}

func (a *accountAccess) authedClient(streams commandIO) (*cpClient, error) {
	cfg, err := a.requireAuth(streams)
	if err != nil {
		return nil, err
	}
	return a.client(streams, cfg), nil
}

// resolveContainer accepts either a UUID or a name. When given a name, list
// containers and pick the one with a matching name. A name shared by a debug
// and a production container is ambiguous; the caller must use the ID.
func resolveContainer(client *cpClient, identifier string) (*containerView, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return nil, fmt.Errorf("container identifier is empty")
	}
	if looksLikeUUID(id) {
		var c containerView
		if _, err := client.do("GET", pathf("/api/containers/%s", id), nil, nil, &c); err != nil {
			return nil, err
		}
		return &c, nil
	}

	var list []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &list); err != nil {
		return nil, err
	}
	matches := make([]containerView, 0, 2)
	for _, c := range list {
		if c.Name == id {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no container named %q; see `tinfoil container list`", id)
	case 1:
		c := matches[0]
		return &c, nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%q names more than one container; use the ID:\n", id)
		for _, c := range matches {
			mode := "production"
			if c.Debug {
				mode = "debug"
			}
			fmt.Fprintf(&b, "  %s  %-10s  %s\n", c.ID, mode, c.Domain)
		}
		return nil, fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
	}
}

// resolveContainerDetail is resolveContainer followed by the single-container
// view, which is the only one that carries volume fields.
func resolveContainerDetail(client *cpClient, identifier string) (*containerView, error) {
	c, err := resolveContainer(client, identifier)
	if err != nil {
		return nil, err
	}
	if looksLikeUUID(strings.TrimSpace(identifier)) {
		return c, nil
	}
	var full containerView
	if _, err := client.do("GET", pathf("/api/containers/%s", c.ID), nil, nil, &full); err != nil {
		return nil, err
	}
	return &full, nil
}

func looksLikeUUID(s string) bool {
	// 8-4-4-4-12 hex; cheap check that avoids importing google/uuid.
	if len(s) != 36 {
		return false
	}
	for i, ch := range s {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}
	return true
}

func parseKeyValues(in []string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for _, raw := range in {
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("invalid variable %q: expected KEY=VALUE", raw)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("invalid variable %q: empty key", raw)
		}
		out[k] = v
	}
	return out, nil
}

// buildLifecycleBody assembles the request body shared by /deploy and
// /update. Only fields whose flag was set on the command line are included
// so the controlplane keeps the existing values for the rest.
func buildLifecycleBody(cmd *cobra.Command,
	tag string,
	variables, secrets, sshKeys []string,
	debug, markLatestRelease, customDomain, host string,
) (map[string]any, error) {
	body := map[string]any{}
	if cmd.Flags().Changed("tag") && tag != "" {
		body["tag"] = tag
	}
	if cmd.Flags().Changed("variable") {
		vars, err := parseKeyValues(variables)
		if err != nil {
			return nil, err
		}
		if vars == nil {
			vars = map[string]string{}
		}
		body["variables"] = vars
	}
	if cmd.Flags().Changed("secret") {
		selection, err := parseSecretSelection(secrets)
		if err != nil {
			return nil, err
		}
		body["secrets"] = selection
	}
	if cmd.Flags().Changed("ssh-key") {
		if sshKeys == nil {
			sshKeys = []string{}
		}
		body["ssh_keys"] = sshKeys
	}
	if cmd.Flags().Changed("debug") {
		v, err := parseTriBool(debug)
		if err != nil {
			return nil, fmt.Errorf("--debug: %w", err)
		}
		body["debug"] = v
	}
	if err := setMarkLatestRelease(cmd, body, markLatestRelease); err != nil {
		return nil, err
	}
	if cmd.Flags().Changed("custom-domain") {
		body["custom_domain"] = customDomain
	}
	if cmd.Flags().Lookup("host") != nil && cmd.Flags().Changed("host") {
		body["host_name"] = host
	}
	return body, nil
}

// setMarkLatestRelease adds mark_latest_release to body only when the flag was set,
// so an omitted flag defers to the controlplane default.
func setMarkLatestRelease(cmd *cobra.Command, body map[string]any, value string) error {
	if !cmd.Flags().Changed("mark-latest") {
		return nil
	}
	v, err := parseTriBool(value)
	if err != nil {
		return fmt.Errorf("--mark-latest: %w", err)
	}
	body["mark_latest_release"] = v
	return nil
}

// confirmNonCCMode prints the same warning text the dashboard shows when a
// user toggles "Disable Confidential Compute", then requires the user to type
// "yes" before proceeding. --yes bypasses the prompt for scripted use. When
// stdin is not a TTY and --yes was not passed, abort rather than block.
func confirmNonCCMode(streams commandIO, containerCreateOpts *containerCreateOptions) error {
	fmt.Fprintln(streams.err, "EXPERIMENTAL: Disable Confidential Compute")
	fmt.Fprintln(streams.err)
	fmt.Fprintln(streams.err, "Disables memory encryption and hardware attestation for this container.")
	fmt.Fprintln(streams.err, "It will not provide CC guarantees and is not suitable for production")
	fmt.Fprintln(streams.err, "workloads. Intended for benchmarking against non-CC baselines.")
	fmt.Fprintln(streams.err)
	fmt.Fprintln(streams.err, "WARNING: This container will deploy without confidential computing")
	fmt.Fprintln(streams.err, "protections. The host operator can read memory and observe execution.")
	fmt.Fprintln(streams.err)
	return confirmYes(streams, containerCreateOpts.createYes, "--disable-cc-mode")
}

func confirmYes(streams commandIO, skip bool, what string) error {
	if skip {
		fmt.Fprintln(streams.err, "Proceeding (--yes).")
		return nil
	}
	if !term.IsTerminal(int(streamFD(streams.in))) {
		return fmt.Errorf("%s requires interactive confirmation; pass --yes to skip the prompt", what)
	}
	fmt.Fprint(streams.err, "Type \"yes\" to proceed: ")
	scanner := bufio.NewScanner(streams.in)
	if !scanner.Scan() {
		return fmt.Errorf("aborted")
	}
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

func parseTriBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "t", "yes", "y", "1", "on":
		return true, nil
	case "false", "f", "no", "n", "0", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected true/false, got %q", s)
	}
}

func formatInts(in []int) string {
	if len(in) == 0 {
		return "-"
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(out, ",")
}

func renderContainer(streams commandIO, outputOpts *outputOptions, c containerView) error {
	return renderContainerDetail(streams, outputOpts, c, nil)
}

// renderContainerDetail prints c with its declared volumes; attached maps a
// slot to its volume when known, otherwise the view's volume ID is shown.
func renderContainerDetail(streams commandIO, outputOpts *outputOptions, c containerView, attached map[string]volumeView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, c)
	}
	fmt.Fprintf(streams.out, "ID:           %s\n", c.ID)
	fmt.Fprintf(streams.out, "Name:         %s\n", c.Name)
	fmt.Fprintf(streams.out, "Status:       %s\n", statusLabel(c.Status))
	if c.ConfigName != "" {
		fmt.Fprintf(streams.out, "Config:       %s\n", c.ConfigName)
		fmt.Fprintf(streams.out, "Release:      %s\n", c.CurrentTag)
	} else if c.Source == containerSourceLocal {
		fmt.Fprintf(streams.out, "Config:       local\n")
	} else {
		fmt.Fprintf(streams.out, "Repo:         %s@%s\n", c.Repo, c.CurrentTag)
	}
	if c.ProjectID != "" {
		fmt.Fprintf(streams.out, "Project:      %s\n", c.ProjectID)
	}
	if c.Domain != "" {
		fmt.Fprintf(streams.out, "Domain:       %s\n", c.Domain)
	}
	if c.InternalDomain != "" && c.InternalDomain != c.Domain {
		fmt.Fprintf(streams.out, "Internal:     %s\n", c.InternalDomain)
	}
	if c.HostName != "" {
		fmt.Fprintf(streams.out, "Host:         %s (cpu=%s gpu=%s)\n", c.HostName, c.HostCpuType, c.HostGpuType)
	}
	fmt.Fprintf(streams.out, "Resources:    cpus=%d gpus=%d mem=%dMB\n", c.CPUs, c.GPUs, c.MemoryMB)
	if c.MarkLatestRelease != nil {
		fmt.Fprintf(streams.out, "Mark latest:  %t\n", *c.MarkLatestRelease)
	}
	if c.Debug {
		fmt.Fprintf(streams.out, "Debug:        yes (SSH enabled, does not pass attestation)\n")
	}
	if c.UpdateTag != "" && c.CandidateHeld() {
		fmt.Fprintf(streams.out, "Held:         yes (this version is waiting for review; promote to switch traffic)\n")
	}
	if c.DisableCCMode {
		fmt.Fprintf(streams.out, "Confidential: disabled\n")
	}
	if c.UpdateStrategy == updateStrategyReplace {
		fmt.Fprintf(streams.out, "Updates:      replace (%s; updates cause downtime)\n", replaceReason(c))
	}
	if c.SSHPort > 0 {
		fmt.Fprintf(streams.out, "SSH port:     %d\n", c.SSHPort)
	}
	if vars, _ := decodeContainerVariables(c.Variables); len(vars) > 0 {
		keys := make([]string, 0, len(vars))
		for k := range vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(streams.out, "Variables:    %s\n", strings.Join(keys, ", "))
	}
	if len(c.Secrets) > 0 {
		fmt.Fprintf(streams.out, "Secrets:      %s\n", strings.Join(c.Secrets, ", "))
	}
	if len(c.SSHKeys) > 0 {
		fmt.Fprintf(streams.out, "SSH keys:     %s\n", strings.Join(c.SSHKeys, ", "))
	}
	label := "Volumes:      "
	for _, slot := range c.VolumeSlots {
		switch v, ok := attached[slot.Name]; {
		case ok:
			fmt.Fprintf(streams.out, "%s%s ← %s (%s)\n", label, slot.Name, v.Name, formatSize(v.SizeBytes))
		case c.Volumes[slot.Name] != "":
			fmt.Fprintf(streams.out, "%s%s ← %s\n", label, slot.Name, c.Volumes[slot.Name])
		default:
			fmt.Fprintf(streams.out, "%s%s (none attached)\n", label, slot.Name)
		}
		label = strings.Repeat(" ", len(label))
	}
	printVolumeUnlockGuidance(streams.out, c.VolumeSlots)
	if c.UpdateTag != "" {
		fmt.Fprintf(streams.out, "Updating to:  %s (%s)\n", c.UpdateTag, updateLabel(c))
	}
	if message := containerFailureMessage(c); message != "" {
		fmt.Fprintf(streams.out, "Error:        %s\n", humanVolumeMessage(message))
	}
	printBootStages(streams.out, c.BootStages)
	printContainerConnections(streams.out, c)
	return nil
}

func renderContainers(streams commandIO, outputOpts *outputOptions, list []containerView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(streams.out, "No containers.")
		return nil
	}
	fmt.Fprintf(streams.out, "%-24s  %-10s  %-30s  %-10s  %s\n", "NAME", "STATUS", "DOMAIN", "TAG", "SOURCE")
	for _, c := range list {
		domain := c.Domain
		if domain == "" {
			domain = "-"
		}
		tag := c.CurrentTag
		if tag == "" {
			tag = "-"
		}
		source := c.Repo
		if c.ConfigName != "" {
			source = c.ConfigName
		} else if c.Source == containerSourceLocal {
			source = containerSourceLocal
		}
		fmt.Fprintf(streams.out, "%-24s  %-10s  %-30s  %-10s  %s\n",
			truncate(c.Name, 24), statusLabel(c.Status), truncate(domain, 30), truncate(tag, 10), source,
		)
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return s[:max-1] + "…"
}

func printJSON(streams commandIO, v any) error {
	enc := json.NewEncoder(streams.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// decodeContainerVariables handles both the JSON-object form and the
// base64-encoded JSONB form returned by the controlplane (the database column
// is `[]byte`, which encoding/json renders as a base64 string).
func decodeContainerVariables(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	out := make(map[string]string)
	if err := json.Unmarshal(raw, &out); err == nil {
		return out, nil
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(decoded, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func prettyJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return raw
	}
	return out
}

func runContainerDeploy(pollingOpts *pollingOptions, newClient authenticatedClientFactory, containerDeployOpts *containerDeployOptions, outputOpts *outputOptions, waitOpts *waitOptions, cmd *cobra.Command, args []string) error {
	body, err := buildLifecycleBody(cmd,
		containerDeployOpts.deployTag, containerDeployOpts.deployVariables, containerDeployOpts.deploySecrets, containerDeployOpts.deploySSHKeys,
		containerDeployOpts.deployDebug, containerDeployOpts.deployMarkLatestRelease, containerDeployOpts.deployCustomDomain, containerDeployOpts.deployHost,
	)
	if err != nil {
		return err
	}

	requests, err := parseVolumeRequests(containerDeployOpts.deployVolumes)
	if err != nil {
		return err
	}

	client, err := newClient(commandStreams(cmd))
	if err != nil {
		return err
	}
	c, err := resolveContainerDetail(client, args[0])
	if err != nil {
		return err
	}
	if err := checkManagedKind(cmd.Annotations[managedKindAnnotation], *c); err != nil {
		return err
	}
	if c.Status == statusFailed && c.ErrorMessage != "" && outputOpts.outputFormat != "json" {
		fmt.Fprintf(commandStreams(cmd).err, "Last attempt failed: %s\n", humanVolumeMessage(c.ErrorMessage))
		fmt.Fprintln(commandStreams(cmd).err, "Deploying again with the same settings; pass flags to change them.")
	}
	if len(requests) > 0 {
		list, err := listVolumes(client)
		if err != nil {
			return err
		}
		volumes, err := resolveVolumeRequests(list.Volumes, requests, nil)
		if err != nil {
			return err
		}
		host, err := volumesHost(volumes, containerDeployOpts.deployHost)
		if err != nil {
			return err
		}
		if containerDeployOpts.deployHost == "" && c.HostName != host {
			return fmt.Errorf("container %s is on host %s but volume %s is on %s; volumes must be on the container's host", c.Name, c.HostName, volumes[0].Name, host)
		}
		attachTarget := *c
		attachTarget.MarkLatestRelease = nil
		if value, ok := body["mark_latest_release"].(bool); ok {
			attachTarget.MarkLatestRelease = &value
		}
		if err := attachVolumes(client, &attachTarget, requests, volumes); err != nil {
			return err
		}
	}
	deployed, err := postContainerAction(client, c.ID, "deploy", body)
	if err != nil {
		return withAttachHint(err, c)
	}
	attached, err := loadContainerVolumes(client, deployed)
	if err != nil {
		return err
	}
	return followAndRender(pollingOpts, commandStreams(cmd), outputOpts, waitOpts, client, deployed, attached)
}

func runContainerUpdate(pollingOpts *pollingOptions, newClient authenticatedClientFactory, containerUpdateOpts *containerUpdateOptions, outputOpts *outputOptions, waitOpts *waitOptions, cmd *cobra.Command, args []string) error {
	body, err := buildLifecycleBody(cmd,
		containerUpdateOpts.updateTag, containerUpdateOpts.updateVariables, containerUpdateOpts.updateSecrets, containerUpdateOpts.updateSSHKeys,
		containerUpdateOpts.updateDebug, containerUpdateOpts.updateMarkLatestRelease, containerUpdateOpts.updateCustomDomain, "",
	)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("hold") {
		hold, err := parseTriBool(containerUpdateOpts.updateHold)
		if err != nil {
			return fmt.Errorf("--hold: %w", err)
		}
		body["hold"] = hold
	} else if cmd.Annotations[managedKindAnnotation] != "" {
		body["hold"] = false
	}

	client, err := newClient(commandStreams(cmd))
	if err != nil {
		return err
	}
	c, err := resolveContainerDetail(client, args[0])
	if err != nil {
		return err
	}
	if err := checkManagedKind(cmd.Annotations[managedKindAnnotation], *c); err != nil {
		return err
	}
	var updated containerView
	if err := postLifecycleUpdate(commandStreams(cmd), outputOpts, client, pathf("/api/containers/%s/update", c.ID), body, &updated, containerUpdateOpts.updateYes, cmd.CommandPath(), func() (updateReview, error) {
		return planContainerUpdate(client, c.ID, body)
	}); err != nil {
		return err
	}
	return followAndRender(pollingOpts, commandStreams(cmd), outputOpts, waitOpts, client, updated, nil)
}

func runContainerMetrics(newClient authenticatedClientFactory, containerMetricsOpts *containerMetricsOptions, cmd *cobra.Command, args []string) error {
	client, err := newClient(commandStreams(cmd))
	if err != nil {
		return err
	}
	c, err := resolveContainer(client, args[0])
	if err != nil {
		return err
	}
	if err := checkManagedKind(cmd.Annotations[managedKindAnnotation], *c); err != nil {
		return err
	}
	q := url.Values{"time": []string{containerMetricsOpts.metricsTime}}
	var raw json.RawMessage
	if _, err := client.do("GET", pathf("/api/containers/%s/metrics", c.ID), q, nil, &raw); err != nil {
		return err
	}
	// Metrics are time-series data; printing JSON is the most useful
	// default. Users who want a chart can pipe into jq.
	commandStreams(cmd).out.Write(prettyJSON(raw))
	fmt.Fprintln(commandStreams(cmd).out)
	return nil
}
