package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// containerView mirrors the controlplane's containerResponse. We only model
// the fields the CLI actually displays or forwards; everything else stays in
// RawMessage form so updates to the API don't break decoding here.
type containerView struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	Repo                 string           `json:"repo"`
	ProjectID            string           `json:"project_id"`
	Status               string           `json:"status"`
	CurrentTag           string           `json:"current_tag"`
	Domain               string           `json:"domain"`
	InternalDomain       string           `json:"internal_domain"`
	HostName             string           `json:"host_name"`
	HostGpuType          string           `json:"host_gpu_type"`
	HostCpuType          string           `json:"host_cpu_type"`
	CPUs                 int              `json:"cpus"`
	GPUs                 int              `json:"gpus"`
	MemoryMB             int              `json:"memory_mb"`
	Variables            json.RawMessage  `json:"variables"`
	Secrets              []string         `json:"secrets"`
	SSHKeys              []string         `json:"ssh_keys"`
	Debug                bool             `json:"debug"`
	Held                 bool             `json:"held"`
	MarkLatestRelease    *bool            `json:"mark_latest_release,omitempty"`
	DisableCCMode        bool             `json:"disable_cc_mode"`
	GithubAppConnected   bool             `json:"github_app_connected"`
	DisplayOrder         int32            `json:"display_order"`
	UpdateTag            string           `json:"update_tag"`
	UpdateStatus         string           `json:"update_status"`
	UpdateType           string           `json:"update_type"`
	UpdateStrategy       string           `json:"update_strategy"`
	UpdateConfig         *candidateConfig `json:"update_config,omitempty"`
	TinfoildDeploymentID string           `json:"tinfoild_deployment_id,omitempty"`
	UpdateDeploymentID   string           `json:"update_deployment_id,omitempty"`
	BootStages           bootStages       `json:"boot_stages"`
	UpdateBootStages     bootStages       `json:"update_boot_stages"`
	ErrorMessage         string           `json:"error_message"`
	CreatedAt            string           `json:"created_at"`
	UpdatedAt            string           `json:"updated_at"`
	SSHPort              int              `json:"ssh_port"`
	HostID               string           `json:"host_id,omitempty"`
	// VolumeSlots are the volumes tinfoil-config.yml declares; Volumes maps a
	// slot to the attached volume ID. Only the single-container view has them.
	VolumeSlots []volumeSlot      `json:"volume_slots,omitempty"`
	Volumes     map[string]string `json:"volumes,omitempty"`
}

type candidateConfig struct {
	Hold *bool `json:"hold,omitempty"`
}

func (c containerView) candidateHeld() bool {
	if c.UpdateConfig != nil && c.UpdateConfig.Hold != nil {
		return *c.UpdateConfig.Hold
	}
	return c.Held
}

// bootStage mirrors one entry of the boot progress tinfoild reports while a
// deployment comes up. Stages nest.
type bootStage struct {
	Name   string      `json:"name"`
	Status string      `json:"status"`
	Stages []bootStage `json:"stages,omitempty"`
}

type bootStages []bootStage

func (stages *bootStages) UnmarshalJSON(raw []byte) error {
	if strings.HasPrefix(strings.TrimSpace(string(raw)), `"`) {
		var decoded []byte
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return fmt.Errorf("decoding boot stages: %w", err)
		}
		raw = decoded
	}
	return json.Unmarshal(raw, (*[]bootStage)(stages))
}

type hostInfo struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	IsDefault          bool   `json:"is_default"`
	AvailableGpuValues []int  `json:"available_gpu_values"`
}

var (
	outputFormat string

	createRepo              string
	createTag               string
	createDebug             bool
	createMarkLatestRelease string
	createDisableCC         bool
	createYes               bool
	createCustomDomain      string
	createHost              string
	createReplaceID         string
	createVariables         []string
	createSecrets           []string
	createSSHKeys           []string
	createVolumes           []string
	createDisplayOrder      int32

	updateTag               string
	updateVariables         []string
	updateSecrets           []string
	updateSSHKeys           []string
	updateDebug             string
	updateHold              string
	updateMarkLatestRelease string
	updateCustomDomain      string
	updateYes               bool

	deployTag               string
	deployVariables         []string
	deploySecrets           []string
	deploySSHKeys           []string
	deployDebug             string
	deployMarkLatestRelease string
	deployCustomDomain      string
	deployHost              string
	deployVolumes           []string

	deleteYes bool
	noWait    bool

	metricsTime string

	cancelRollbackLatest bool

	connectPort     uint
	connectBindAddr string
)

func init() {
	rootCmd.AddCommand(containerCmd)
	containerCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	containerCmd.AddCommand(containerListCmd)
	containerCmd.AddCommand(containerGetCmd)
	containerCmd.AddCommand(containerCreateCmd)
	containerCmd.AddCommand(containerDeleteCmd)
	containerCmd.AddCommand(containerDeployCmd)
	containerCmd.AddCommand(containerStopCmd)
	containerCmd.AddCommand(containerUpdateCmd)
	containerCmd.AddCommand(containerPromoteCmd)
	containerCmd.AddCommand(containerCancelCmd)
	containerCmd.AddCommand(containerMetricsCmd)
	containerCmd.AddCommand(containerHostsCmd)
	containerCmd.AddCommand(containerConnectCmd)

	for _, c := range []*cobra.Command{containerCreateCmd, containerDeployCmd, containerUpdateCmd, containerPromoteCmd} {
		c.Flags().BoolVar(&noWait, "no-wait", false, "Return as soon as the request is accepted instead of following progress")
	}
	containerCancelCmd.Flags().BoolVar(&cancelRollbackLatest, "rollback-latest", false, "Request restoring the repository's latest release to the current production tag")

	containerCreateCmd.Flags().StringVar(&createRepo, "repo", "", "GitHub repo (owner/repo) holding tinfoil-config.yml [required]")
	containerCreateCmd.Flags().StringVar(&createTag, "tag", "", "Repository release tag to deploy [required]")
	containerCreateCmd.Flags().BoolVar(&createDebug, "debug", false, "Enable debug mode (allows SSH into the enclave)")
	containerCreateCmd.Flags().StringVar(&createMarkLatestRelease, "mark-latest", "", "Mark the deployed tag as the repository's latest GitHub release once it is running (default true; pass false to leave the latest release unchanged)")
	containerCreateCmd.Flags().BoolVar(&createDisableCC, "disable-cc-mode", false, "EXPERIMENTAL: disable confidential computing (benchmarks only; requires org entitlement)")
	containerCreateCmd.Flags().BoolVar(&createYes, "yes", false, "Skip interactive confirmation for --disable-cc-mode")
	containerCreateCmd.Flags().StringVar(&createCustomDomain, "custom-domain", "", "Verified custom domain to expose the container on")
	containerCreateCmd.Flags().StringVar(&createHost, "host", "", "Target host name (see 'tinfoil container hosts')")
	containerCreateCmd.Flags().StringVar(&createReplaceID, "replace", "", "ID of an existing container to atomically replace")
	containerCreateCmd.Flags().StringArrayVar(&createVariables, "variable", nil, "Environment variable in KEY=VALUE form; may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&createSecrets, "secret", nil, "Org secret name to mount; may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&createSSHKeys, "ssh-key", nil, "Org SSH key name (debug only); may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&createVolumes, "volume", nil, "Volume to attach before the first deploy, as <id|name>[:<declared name>]; may be repeated")
	containerCreateCmd.Flags().Int32Var(&createDisplayOrder, "display-order", 0, "Sort order of this instance within its project")
	_ = containerCreateCmd.MarkFlagRequired("repo")
	_ = containerCreateCmd.MarkFlagRequired("tag")

	containerDeleteCmd.Flags().BoolVar(&deleteYes, "yes", false, "Skip interactive confirmation")

	containerDeployCmd.Flags().StringVar(&deployTag, "tag", "", "Deploy a different release tag than the saved one")
	containerDeployCmd.Flags().StringArrayVar(&deployVariables, "variable", nil, "Replace the saved environment variables with KEY=VALUE pairs; may be repeated")
	containerDeployCmd.Flags().StringArrayVar(&deploySecrets, "secret", nil, "Replace the saved secrets list (specify all)")
	containerDeployCmd.Flags().StringArrayVar(&deploySSHKeys, "ssh-key", nil, "Replace the saved SSH keys list")
	containerDeployCmd.Flags().StringVar(&deployDebug, "debug", "", "Deploy in debug mode (true/false)")
	containerDeployCmd.Flags().StringVar(&deployMarkLatestRelease, "mark-latest", "", "Mark the deployed tag as the repository's latest GitHub release once it is running (default true; pass false to leave the latest release unchanged)")
	containerDeployCmd.Flags().StringVar(&deployCustomDomain, "custom-domain", "", "Replace the custom domain (empty string clears it)")
	containerDeployCmd.Flags().StringVar(&deployHost, "host", "", "Deploy on a different host (see 'tinfoil container hosts')")
	containerDeployCmd.Flags().StringArrayVar(&deployVolumes, "volume", nil, "Volume to attach before deploying, as <id|name>[:<declared name>]; may be repeated")

	containerUpdateCmd.Flags().StringVar(&updateTag, "tag", "", "Release tag to update to")
	containerUpdateCmd.Flags().StringArrayVar(&updateVariables, "variable", nil, "Replace the saved environment variables with KEY=VALUE pairs; may be repeated")
	containerUpdateCmd.Flags().StringArrayVar(&updateSecrets, "secret", nil, "Replace the saved secrets list (specify all)")
	containerUpdateCmd.Flags().StringArrayVar(&updateSSHKeys, "ssh-key", nil, "Replace the saved SSH keys list")
	containerUpdateCmd.Flags().StringVar(&updateDebug, "debug", "", "Switch debug mode on or off (true/false)")
	containerUpdateCmd.Flags().StringVar(&updateHold, "hold", "", "Hold the new version for review instead of switching traffic automatically (true/false)")
	containerUpdateCmd.Flags().Lookup("hold").NoOptDefVal = "true"
	containerUpdateCmd.Flags().StringVar(&updateMarkLatestRelease, "mark-latest", "", "Mark the deployed tag as the repository's latest GitHub release once it is running (default true; pass false to leave the latest release unchanged)")
	containerUpdateCmd.Flags().StringVar(&updateCustomDomain, "custom-domain", "", "Replace the custom domain (empty string clears it)")
	containerUpdateCmd.Flags().BoolVar(&updateYes, "yes", false, "Skip the downtime confirmation for containers that must be replaced")

	containerMetricsCmd.Flags().StringVar(&metricsTime, "time", "24h", "Time window (e.g. 1h, 24h, 7d)")

	containerConnectCmd.Flags().UintVarP(&connectPort, "port", "p", 8080, "Local port for the verified proxy")
	containerConnectCmd.Flags().StringVarP(&connectBindAddr, "bind", "b", "127.0.0.1", "Address to bind to")

	silenceUsageRecursive(containerCmd)
}

// silenceUsageRecursive walks the command tree and sets SilenceUsage so that
// runtime errors (auth, network, validation) don't dump the help banner.
func silenceUsageRecursive(cmd *cobra.Command) {
	cmd.SilenceUsage = true
	for _, c := range cmd.Commands() {
		silenceUsageRecursive(c)
	}
}

var containerCmd = &cobra.Command{
	Use:          "container",
	Aliases:      []string{"containers", "ct"},
	Short:        "Manage Tinfoil containers",
	SilenceUsage: true,
}

var containerListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List containers in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var list []containerView
		if _, err := client.do("GET", "/api/containers", nil, nil, &list); err != nil {
			return err
		}
		return renderContainers(list)
	},
}

var containerGetCmd = &cobra.Command{
	Use:   "get [id|name]",
	Short: "Show a single container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
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
		return renderContainerDetail(*c, attached)
	},
}

var containerCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{
			"name": args[0],
			"repo": createRepo,
			"tag":  createTag,
		}
		if err := setMarkLatestRelease(cmd, body, createMarkLatestRelease); err != nil {
			return err
		}

		client, err := authedClient()
		if err != nil {
			return err
		}

		vars, err := parseKeyValues(createVariables)
		if err != nil {
			return err
		}

		if createDisableCC {
			if err := confirmNonCCMode(); err != nil {
				return err
			}
		}

		requests, err := parseVolumeRequests(createVolumes)
		if err != nil {
			return err
		}
		// A slot with a key secret cannot run without a disk, so refuse up front
		// with the commands to run rather than creating a container that sits
		// stopped. Slots without one are optional and the container deploys
		// with them empty.
		if len(requests) == 0 {
			slots, err := declaredVolumeSlots(client, createRepo, createTag)
			if err != nil {
				return err
			}
			if required := requiredVolumeSlots(slots); len(required) > 0 {
				return errVolumesRequired(args[0], required, createHost)
			}
		}
		var volumes []volumeView
		if len(requests) > 0 {
			list, err := listVolumes(client)
			if err != nil {
				return err
			}
			if volumes, err = resolveVolumeRequests(list.Volumes, requests); err != nil {
				return err
			}
			host, err := volumesHost(volumes, createHost)
			if err != nil {
				return err
			}
			body["host_name"] = host
		}

		if cmd.Flags().Changed("display-order") {
			body["display_order"] = createDisplayOrder
		}
		if len(vars) > 0 {
			body["variables"] = vars
		}
		if len(createSecrets) > 0 {
			body["secrets"] = createSecrets
		}
		if len(createSSHKeys) > 0 {
			body["ssh_keys"] = createSSHKeys
		}
		if createDebug {
			body["debug"] = true
		}
		if createDisableCC {
			body["disable_cc_mode"] = true
		}
		if createCustomDomain != "" {
			body["custom_domain"] = createCustomDomain
		}
		if createHost != "" && len(requests) == 0 {
			body["host_name"] = createHost
		}
		if createReplaceID != "" {
			body["replace_container_id"] = createReplaceID
		}

		var created containerView
		if _, err := client.do("POST", "/api/containers", nil, body, &created); err != nil {
			return err
		}
		if len(created.VolumeSlots) == 0 {
			if len(requests) > 0 {
				return fmt.Errorf("created %s but it declares no volumes in tinfoil-config.yml; --volume was not applied", created.Name)
			}
			return followAndRender(client, created, nil)
		}
		if len(requests) > 0 {
			if err := attachVolumes(client, &created, requests, volumes); err != nil {
				return fmt.Errorf("created %s but %w", created.Name, err)
			}
		}
		// The controlplane leaves any volume-declaring container stopped after
		// create; deploy it now so optional slots do not strand it.
		var deployed containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/deploy", created.ID), nil, map[string]any{}, &deployed); err != nil {
			return fmt.Errorf("created %s but could not deploy it: %s. Run: tinfoil container deploy %s", created.Name, errMessage(err), created.Name)
		}
		attached, err := loadContainerVolumes(client, deployed)
		if err != nil {
			return err
		}
		return followAndRender(client, deployed, attached)
	},
}

var containerDeleteCmd = &cobra.Command{
	Use:     "delete [id|name]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a container",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleting %s (%s).\n", c.Name, c.ID)
		fmt.Fprintln(os.Stderr, "This removes the container, its saved configuration, and its DNS records. Attached volumes are kept.")
		if err := confirmYes(deleteYes, "container delete"); err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/containers/%s", c.ID), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted container %s (%s)\n", c.Name, c.ID)
		return nil
	},
}

var containerDeployCmd = &cobra.Command{
	Use:   "deploy [id|name]",
	Short: "Deploy a stopped or failed container",
	Long: `Boot a new enclave for a container that has none. Works on stopped and
failed containers, and on a stopping container (the deploy runs once the stop
finishes). Without flags the saved configuration is used; flags replace parts
of it. To change a running container, use "tinfoil container update".`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := buildLifecycleBody(cmd,
			deployTag, deployVariables, deploySecrets, deploySSHKeys,
			deployDebug, deployMarkLatestRelease, deployCustomDomain, deployHost,
		)
		if err != nil {
			return err
		}

		requests, err := parseVolumeRequests(deployVolumes)
		if err != nil {
			return err
		}

		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainerDetail(client, args[0])
		if err != nil {
			return err
		}
		if c.Status == statusFailed && c.ErrorMessage != "" && outputFormat != "json" {
			fmt.Fprintf(os.Stderr, "Last attempt failed: %s\n", c.ErrorMessage)
			fmt.Fprintln(os.Stderr, "Deploying again with the same settings; pass flags to change them.")
		}
		if len(requests) > 0 {
			list, err := listVolumes(client)
			if err != nil {
				return err
			}
			volumes, err := resolveVolumeRequests(list.Volumes, requests)
			if err != nil {
				return err
			}
			host, err := volumesHost(volumes, deployHost)
			if err != nil {
				return err
			}
			if deployHost == "" && c.HostName != host {
				return fmt.Errorf("container %s is on host %s but volume %s is on %s; volumes must be on the container's host", c.Name, c.HostName, volumes[0].Name, host)
			}
			if err := attachVolumes(client, c, requests, volumes); err != nil {
				return err
			}
		}
		var deployed containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/deploy", c.ID), nil, body, &deployed); err != nil {
			return withAttachHint(err, c)
		}
		attached, err := loadContainerVolumes(client, deployed)
		if err != nil {
			return err
		}
		return followAndRender(client, deployed, attached)
	},
}

var containerStopCmd = &cobra.Command{
	Use:   "stop [id|name]",
	Short: "Stop a running container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		var stopped containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/stop", c.ID), nil, nil, &stopped); err != nil {
			return err
		}
		if outputFormat != "json" {
			fmt.Printf("Stopping %s. Its configuration and volumes are kept; run \"tinfoil container deploy %s\" to bring it back.\n", c.Name, c.Name)
		}
		return renderContainer(stopped)
	},
}

var containerUpdateCmd = &cobra.Command{
	Use:   "update [id|name]",
	Short: "Update a running container to a new tag or configuration",
	Long: `Replace the running version of a container. Single-GPU containers without
persistent volumes boot the new version alongside the current one and switch
traffic when it is running (no downtime); pass --hold=true to hold the new
version for review until "tinfoil container promote". Multi-GPU containers and
containers with persistent volumes must stop the current version first, so the
command asks you to confirm the downtime unless --yes is given.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := buildLifecycleBody(cmd,
			updateTag, updateVariables, updateSecrets, updateSSHKeys,
			updateDebug, updateMarkLatestRelease, updateCustomDomain, "",
		)
		if err != nil {
			return err
		}
		hold := false
		if cmd.Flags().Changed("hold") {
			hold, err = parseTriBool(updateHold)
			if err != nil {
				return fmt.Errorf("--hold: %w", err)
			}
			body["hold"] = hold
		}

		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainerDetail(client, args[0])
		if err != nil {
			return err
		}
		if c.UpdateStrategy == updateStrategyReplace {
			if hold {
				return fmt.Errorf("holding for review is not available for %s: %s, so the update replaces the running enclave instead of starting the new version alongside it", c.Name, replaceReason(*c))
			}
			if err := confirmDowntime(*c); err != nil {
				return err
			}
			body["confirm_downtime"] = true
		}
		var updated containerView
		if err := postLifecycleUpdate(client, pathf("/api/containers/%s/update", c.ID), body, &updated, updateYes, "container update", []string{c.Name}); err != nil {
			return err
		}
		return followAndRender(client, updated, nil)
	},
}

var containerMetricsCmd = &cobra.Command{
	Use:   "metrics [id|name]",
	Short: "Show container resource metrics",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		q := url.Values{"time": []string{metricsTime}}
		var raw json.RawMessage
		if _, err := client.do("GET", pathf("/api/containers/%s/metrics", c.ID), q, nil, &raw); err != nil {
			return err
		}
		// Metrics are time-series data; printing JSON is the most useful
		// default. Users who want a chart can pipe into jq.
		os.Stdout.Write(prettyJSON(raw))
		fmt.Println()
		return nil
	},
}

var containerHostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "List container hosts available to your organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var hosts []hostInfo
		if _, err := client.do("GET", "/api/containers/hosts", nil, nil, &hosts); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(hosts)
		}
		if len(hosts) == 0 {
			fmt.Println("No container hosts available.")
			return nil
		}
		fmt.Printf("%-24s  %-10s  %s\n", "NAME", "DEFAULT", "GPU SIZES")
		for _, h := range hosts {
			fmt.Printf("%-24s  %-10v  %s\n", h.Name, h.IsDefault, formatInts(h.AvailableGpuValues))
		}
		return nil
	},
}

var containerPromoteCmd = &cobra.Command{
	Use:   "promote [id|name]",
	Short: "Switch traffic to an update that was held for review",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
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
		if outputFormat != "json" {
			fmt.Printf("Promoted update on %s; traffic is switching to %s.\n", c.Name, promoted.CurrentTag)
		}
		return followAndRender(client, promoted, nil)
	},
}

var containerCancelCmd = &cobra.Command{
	Use:   "cancel [id|name]",
	Short: "Cancel an update and keep the current version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
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
		if cancelRollbackLatest {
			body = map[string]bool{"rollback_latest": true}
			response = &acknowledgment
		}
		status, err := client.do("POST", pathf("/api/containers/%s/update/cancel", c.ID), nil, body, response)
		if err != nil {
			if cancelRollbackLatest && status == http.StatusOK {
				return fmt.Errorf("update cancellation may have completed, but the controlplane did not confirm latest release restoration: %w", err)
			}
			return err
		}
		if cancelRollbackLatest {
			if status != http.StatusOK || !acknowledgment.RollbackLatest || strings.TrimSpace(acknowledgment.Tag) == "" {
				return fmt.Errorf("update cancellation may have completed, but the controlplane did not confirm latest release restoration (HTTP %d)", status)
			}
			fmt.Printf("Canceled in-progress update on %s; latest release restoration to %s requested\n", c.Name, acknowledgment.Tag)
			return nil
		}
		fmt.Printf("Canceled update on %s; %s keeps running.\n", c.Name, c.CurrentTag)
		return nil
	},
}

var containerConnectCmd = &cobra.Command{
	Use:   "connect [id|name]",
	Short: "Run a verified proxy to a deployed container",
	Long: `Resolve a deployed container by name (or ID), look up its enclave domain
and source repository, then start a local proxy that verifies the enclave's
attestation and forwards HTTP requests to it. This is a convenience around
` + "`tinfoil proxy -e <domain> -r <repo>`" + `.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		host := strings.TrimSpace(c.Domain)
		if host == "" {
			host = strings.TrimSpace(c.InternalDomain)
		}
		if host == "" {
			return fmt.Errorf("container %s has no domain (status=%s) — cannot connect", c.Name, c.Status)
		}
		if c.Repo == "" {
			return fmt.Errorf("container %s has no repo recorded — cannot connect", c.Name)
		}
		fmt.Printf("Connecting verified proxy to %s (%s) for repo %s\n", c.Name, host, c.Repo)

		enclaveHost = host
		repo = c.Repo
		listenAddr = connectBindAddr
		listenPort = connectPort
		return proxyCmd.RunE(proxyCmd, nil)
	},
}

func authedClient() (*cpClient, error) {
	cfg, err := requireAuth()
	if err != nil {
		return nil, err
	}
	return newCPClient(cfg), nil
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
		return nil, fmt.Errorf("no container named %q (use the container ID or `tinfoil container list`)", id)
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
		if secrets == nil {
			secrets = []string{}
		}
		body["secrets"] = secrets
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
func confirmNonCCMode() error {
	fmt.Fprintln(os.Stderr, "EXPERIMENTAL: Disable Confidential Compute")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Disables memory encryption and hardware attestation for this container.")
	fmt.Fprintln(os.Stderr, "It will not provide CC guarantees and is not suitable for production")
	fmt.Fprintln(os.Stderr, "workloads. Intended for benchmarking against non-CC baselines.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "WARNING: This container will deploy without confidential computing")
	fmt.Fprintln(os.Stderr, "protections. The host operator can read memory and observe execution.")
	fmt.Fprintln(os.Stderr)
	return confirmYes(createYes, "--disable-cc-mode")
}

func confirmYes(skip bool, what string) error {
	if skip {
		fmt.Fprintln(os.Stderr, "Proceeding (--yes).")
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("%s requires interactive confirmation; pass --yes to skip the prompt", what)
	}
	fmt.Fprint(os.Stderr, "Type \"yes\" to proceed: ")
	scanner := bufio.NewScanner(os.Stdin)
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

func renderContainer(c containerView) error {
	return renderContainerDetail(c, nil)
}

// renderContainerDetail prints c with its declared volumes; attached maps a
// slot to its volume when known, otherwise the view's volume ID is shown.
func renderContainerDetail(c containerView, attached map[string]volumeView) error {
	if outputFormat == "json" {
		return printJSON(c)
	}
	fmt.Printf("ID:           %s\n", c.ID)
	fmt.Printf("Name:         %s\n", c.Name)
	fmt.Printf("Status:       %s\n", statusLabel(c.Status))
	fmt.Printf("Repo:         %s@%s\n", c.Repo, c.CurrentTag)
	if c.ProjectID != "" {
		fmt.Printf("Project:      %s\n", c.ProjectID)
	}
	if c.Domain != "" {
		fmt.Printf("Domain:       %s\n", c.Domain)
	}
	if c.InternalDomain != "" && c.InternalDomain != c.Domain {
		fmt.Printf("Internal:     %s\n", c.InternalDomain)
	}
	if c.HostName != "" {
		fmt.Printf("Host:         %s (cpu=%s gpu=%s)\n", c.HostName, c.HostCpuType, c.HostGpuType)
	}
	fmt.Printf("Resources:    cpus=%d gpus=%d mem=%dMB\n", c.CPUs, c.GPUs, c.MemoryMB)
	if c.MarkLatestRelease != nil {
		fmt.Printf("Mark latest:  %t\n", *c.MarkLatestRelease)
	}
	if c.Debug {
		fmt.Printf("Debug:        yes (SSH enabled, does not pass attestation)\n")
	}
	if c.UpdateTag != "" && c.candidateHeld() {
		fmt.Printf("Held:         yes (this version is waiting for review; promote to switch traffic)\n")
	}
	if c.DisableCCMode {
		fmt.Printf("Confidential: disabled\n")
	}
	if c.UpdateStrategy == updateStrategyReplace {
		fmt.Printf("Updates:      replace (%s; updates cause downtime)\n", replaceReason(c))
	}
	if c.SSHPort > 0 {
		fmt.Printf("SSH port:     %d\n", c.SSHPort)
	}
	if vars, _ := decodeContainerVariables(c.Variables); len(vars) > 0 {
		keys := make([]string, 0, len(vars))
		for k := range vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("Variables:    %s\n", strings.Join(keys, ", "))
	}
	if len(c.Secrets) > 0 {
		fmt.Printf("Secrets:      %s\n", strings.Join(c.Secrets, ", "))
	}
	if len(c.SSHKeys) > 0 {
		fmt.Printf("SSH keys:     %s\n", strings.Join(c.SSHKeys, ", "))
	}
	label := "Volumes:      "
	for _, slot := range c.VolumeSlots {
		switch v, ok := attached[slot.Name]; {
		case ok:
			fmt.Printf("%s%s ← %s (%s)\n", label, slot.Name, v.Name, formatSize(v.SizeBytes))
		case c.Volumes[slot.Name] != "":
			fmt.Printf("%s%s ← %s\n", label, slot.Name, c.Volumes[slot.Name])
		default:
			fmt.Printf("%s%s (none attached)\n", label, slot.Name)
		}
		label = strings.Repeat(" ", len(label))
	}
	if c.UpdateTag != "" {
		fmt.Printf("Updating to:  %s (%s)\n", c.UpdateTag, updateLabel(c))
	}
	if c.ErrorMessage != "" {
		fmt.Printf("Error:        %s\n", c.ErrorMessage)
	}
	return nil
}

func renderContainers(list []containerView) error {
	if outputFormat == "json" {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No containers.")
		return nil
	}
	fmt.Printf("%-24s  %-10s  %-30s  %-10s  %s\n", "NAME", "STATUS", "DOMAIN", "TAG", "REPO")
	for _, c := range list {
		domain := c.Domain
		if domain == "" {
			domain = "-"
		}
		tag := c.CurrentTag
		if tag == "" {
			tag = "-"
		}
		fmt.Printf("%-24s  %-10s  %-30s  %-10s  %s\n",
			truncate(c.Name, 24), statusLabel(c.Status), truncate(domain, 30), truncate(tag, 10), c.Repo,
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

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
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
