package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// containerView mirrors the controlplane's containerResponse. We only model
// the fields the CLI actually displays or forwards; everything else stays in
// RawMessage form so updates to the API don't break decoding here.
type containerView struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Repo               string            `json:"repo"`
	Status             string            `json:"status"`
	CurrentTag         string            `json:"current_tag"`
	Domain             string            `json:"domain"`
	InternalDomain     string            `json:"internal_domain"`
	HostName           string            `json:"host_name"`
	HostGpuType        string            `json:"host_gpu_type"`
	HostCpuType        string            `json:"host_cpu_type"`
	CPUs               int               `json:"cpus"`
	GPUs               int               `json:"gpus"`
	MemoryMB           int               `json:"memory_mb"`
	Variables          json.RawMessage   `json:"variables"`
	Secrets            []string          `json:"secrets"`
	SSHKeys            []string          `json:"ssh_keys"`
	Debug              bool              `json:"debug"`
	Staging            bool              `json:"staging"`
	GithubAppConnected bool              `json:"github_app_connected"`
	AutoUpdate         bool              `json:"auto_update"`
	GroupName          *string           `json:"group_name"`
	GroupOrder         int               `json:"group_order"`
	DisplayOrder       int               `json:"display_order"`
	UpdateTag          string            `json:"update_tag"`
	UpdateStatus       string            `json:"update_status"`
	UpdateType         string            `json:"update_type"`
	ErrorMessage       string            `json:"error_message"`
	CreatedAt          string            `json:"created_at"`
	UpdatedAt          string            `json:"updated_at"`
	SSHPort            int               `json:"ssh_port"`
}

type hostInfo struct {
	Name               string `json:"name"`
	IsDefault          bool   `json:"is_default"`
	AvailableGpuValues []int  `json:"available_gpu_values"`
}

var (
	outputFormat string

	createRepo         string
	createTag          string
	createDebug        bool
	createStaging      bool
	createCustomDomain string
	createHost         string
	createReplaceID    string
	createVariables    []string
	createSecrets      []string
	createSSHKeys      []string

	relaunchTag          string
	relaunchVariables    []string
	relaunchSecrets      []string
	relaunchSSHKeys      []string
	relaunchDebug        string
	relaunchStaging      string
	relaunchCustomDomain string
	relaunchHost         string

	startTag          string
	startVariables    []string
	startSecrets      []string
	startSSHKeys      []string
	startDebug        string
	startStaging      string
	startCustomDomain string
	startHost         string

	groupName         string
	groupOrder        int32
	groupDisplayOrder int32
	groupUngroup      bool

	autoUpdateOn  bool
	autoUpdateOff bool

	metricsTime string

	connectPort     uint
	connectBindAddr string

	containerDebugSelector bool
	useDebugFilter         bool
)

func init() {
	rootCmd.AddCommand(containerCmd)
	containerCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	containerCmd.AddCommand(containerListCmd)
	containerCmd.AddCommand(containerGetCmd)
	containerCmd.AddCommand(containerCreateCmd)
	containerCmd.AddCommand(containerDeleteCmd)
	containerCmd.AddCommand(containerStartCmd)
	containerCmd.AddCommand(containerStopCmd)
	containerCmd.AddCommand(containerRelaunchCmd)
	containerCmd.AddCommand(containerAutoUpdateCmd)
	containerCmd.AddCommand(containerMetricsCmd)
	containerCmd.AddCommand(containerHostsCmd)
	containerCmd.AddCommand(containerGroupCmd)
	containerCmd.AddCommand(containerUpdateCmd)
	containerCmd.AddCommand(containerConnectCmd)

	containerUpdateCmd.AddCommand(containerUpdateStatusCmd)
	containerUpdateCmd.AddCommand(containerUpdateAcceptCmd)
	containerUpdateCmd.AddCommand(containerUpdateCancelCmd)

	containerCreateCmd.Flags().StringVar(&createRepo, "repo", "", "GitHub repo (owner/repo) holding tinfoil-config.yml [required]")
	containerCreateCmd.Flags().StringVar(&createTag, "tag", "", "Repository release tag to deploy [required]")
	containerCreateCmd.Flags().BoolVar(&createDebug, "debug", false, "Enable debug mode (allows SSH into the enclave)")
	containerCreateCmd.Flags().BoolVar(&createStaging, "staging", false, "Use staging mode (lower-trust environment)")
	containerCreateCmd.Flags().StringVar(&createCustomDomain, "custom-domain", "", "Verified custom domain to expose the container on")
	containerCreateCmd.Flags().StringVar(&createHost, "host", "", "Target host name (see 'tinfoil container hosts')")
	containerCreateCmd.Flags().StringVar(&createReplaceID, "replace", "", "ID of an existing container to atomically replace")
	containerCreateCmd.Flags().StringArrayVar(&createVariables, "variable", nil, "Environment variable in KEY=VALUE form; may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&createSecrets, "secret", nil, "Org secret name to mount; may be repeated")
	containerCreateCmd.Flags().StringArrayVar(&createSSHKeys, "ssh-key", nil, "Org SSH key name (debug only); may be repeated")
	_ = containerCreateCmd.MarkFlagRequired("repo")
	_ = containerCreateCmd.MarkFlagRequired("tag")

	addDebugSelector(containerGetCmd)
	addDebugSelector(containerDeleteCmd)
	addDebugSelector(containerStartCmd)
	addDebugSelector(containerStopCmd)
	addDebugSelector(containerRelaunchCmd)
	addDebugSelector(containerAutoUpdateCmd)
	addDebugSelector(containerMetricsCmd)
	addDebugSelector(containerGroupCmd)
	addDebugSelector(containerUpdateStatusCmd)
	addDebugSelector(containerUpdateAcceptCmd)
	addDebugSelector(containerUpdateCancelCmd)
	addDebugSelector(containerConnectCmd)

	containerStartCmd.Flags().StringVar(&startTag, "tag", "", "Override the deployed tag")
	containerStartCmd.Flags().StringArrayVar(&startVariables, "variable", nil, "Override environment variable in KEY=VALUE form")
	containerStartCmd.Flags().StringArrayVar(&startSecrets, "secret", nil, "Override secrets list (specify all)")
	containerStartCmd.Flags().StringArrayVar(&startSSHKeys, "ssh-key", nil, "Override SSH keys list")
	containerStartCmd.Flags().StringVar(&startDebug, "debug", "", "Override debug mode (true/false)")
	containerStartCmd.Flags().StringVar(&startStaging, "staging", "", "Override staging mode (true/false)")
	containerStartCmd.Flags().StringVar(&startCustomDomain, "custom-domain", "", "Override custom domain (empty string clears it)")
	containerStartCmd.Flags().StringVar(&startHost, "host", "", "Move stopped container to a different host")

	containerRelaunchCmd.Flags().StringVar(&relaunchTag, "tag", "", "Override the deployed tag")
	containerRelaunchCmd.Flags().StringArrayVar(&relaunchVariables, "variable", nil, "Override environment variable in KEY=VALUE form")
	containerRelaunchCmd.Flags().StringArrayVar(&relaunchSecrets, "secret", nil, "Override secrets list (specify all)")
	containerRelaunchCmd.Flags().StringArrayVar(&relaunchSSHKeys, "ssh-key", nil, "Override SSH keys list")
	containerRelaunchCmd.Flags().StringVar(&relaunchDebug, "debug", "", "Override debug mode (true/false)")
	containerRelaunchCmd.Flags().StringVar(&relaunchStaging, "staging", "", "Override staging mode (true/false)")
	containerRelaunchCmd.Flags().StringVar(&relaunchCustomDomain, "custom-domain", "", "Override custom domain (empty string clears it)")
	containerRelaunchCmd.Flags().StringVar(&relaunchHost, "host", "", "Move failed container to a different host")

	containerAutoUpdateCmd.Flags().BoolVar(&autoUpdateOn, "on", false, "Enable auto-update")
	containerAutoUpdateCmd.Flags().BoolVar(&autoUpdateOff, "off", false, "Disable auto-update")

	containerMetricsCmd.Flags().StringVar(&metricsTime, "time", "24h", "Time window (e.g. 1h, 24h, 7d)")

	containerGroupCmd.Flags().StringVar(&groupName, "name", "", "Group name to assign")
	containerGroupCmd.Flags().BoolVar(&groupUngroup, "ungroup", false, "Remove the container from any group")
	containerGroupCmd.Flags().Int32Var(&groupOrder, "group-order", 0, "Order of the group itself")
	containerGroupCmd.Flags().Int32Var(&groupDisplayOrder, "display-order", 0, "Display order within the group")

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

func addDebugSelector(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&containerDebugSelector, "debug-mode", false, "Match containers in debug mode when resolving by name")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		useDebugFilter = cmd.Flags().Changed("debug-mode")
		return nil
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
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		return renderContainer(*c)
	},
}

var containerCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}

		vars, err := parseKeyValues(createVariables)
		if err != nil {
			return err
		}

		body := map[string]any{
			"name": args[0],
			"repo": createRepo,
			"tag":  createTag,
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
		if createStaging {
			body["staging"] = true
		}
		if createCustomDomain != "" {
			body["custom_domain"] = createCustomDomain
		}
		if createHost != "" {
			body["host_name"] = createHost
		}
		if createReplaceID != "" {
			body["replace_container_id"] = createReplaceID
		}

		var created containerView
		if _, err := client.do("POST", "/api/containers", nil, body, &created); err != nil {
			return err
		}
		return renderContainer(created)
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
		if _, err := client.do("DELETE", pathf("/api/containers/%s", c.ID), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted container %s (%s)\n", c.Name, c.ID)
		return nil
	},
}

var containerStartCmd = &cobra.Command{
	Use:   "start [id|name]",
	Short: "Start a stopped container",
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
		body, err := buildLifecycleBody(cmd,
			startTag, startVariables, startSecrets, startSSHKeys,
			startDebug, startStaging, startCustomDomain, startHost,
		)
		if err != nil {
			return err
		}
		var updated containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/start", c.ID), nil, body, &updated); err != nil {
			return err
		}
		return renderContainer(updated)
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
		var updated containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/stop", c.ID), nil, nil, &updated); err != nil {
			return err
		}
		return renderContainer(updated)
	},
}

var containerRelaunchCmd = &cobra.Command{
	Use:   "relaunch [id|name]",
	Short: "Redeploy a running or failed container",
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
		body, err := buildLifecycleBody(cmd,
			relaunchTag, relaunchVariables, relaunchSecrets, relaunchSSHKeys,
			relaunchDebug, relaunchStaging, relaunchCustomDomain, relaunchHost,
		)
		if err != nil {
			return err
		}
		// /relaunch requires a body even when empty so the controlplane decoder
		// can read fields it doesn't necessarily set.
		if body == nil {
			body = map[string]any{}
		}
		var updated containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/relaunch", c.ID), nil, body, &updated); err != nil {
			return err
		}
		return renderContainer(updated)
	},
}

var containerAutoUpdateCmd = &cobra.Command{
	Use:   "auto-update [id|name]",
	Short: "Toggle auto-update for a GitHub-connected container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if autoUpdateOn == autoUpdateOff {
			return fmt.Errorf("specify exactly one of --on or --off")
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		body := map[string]any{"auto_update": autoUpdateOn}
		var updated containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/auto-update", c.ID), nil, body, &updated); err != nil {
			return err
		}
		fmt.Printf("auto_update=%v on %s\n", updated.AutoUpdate, updated.Name)
		return nil
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

var containerGroupCmd = &cobra.Command{
	Use:   "group [id|name]",
	Short: "Move a container into (or out of) a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !groupUngroup && groupName == "" {
			return fmt.Errorf("specify --name <group> or --ungroup")
		}
		if groupUngroup && groupName != "" {
			return fmt.Errorf("--name and --ungroup are mutually exclusive")
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		c, err := resolveContainer(client, args[0])
		if err != nil {
			return err
		}
		// The controlplane has no partial-update semantics for these fields;
		// any value sent (including 0) is written verbatim. Preserve the
		// container's current order when the user didn't pass the flag, so
		// `container group my-app --name foo` doesn't silently reset
		// existing positions.
		groupOrderToSend := int32(c.GroupOrder)
		if cmd.Flags().Changed("group-order") {
			groupOrderToSend = groupOrder
		}
		displayOrderToSend := int32(c.DisplayOrder)
		if cmd.Flags().Changed("display-order") {
			displayOrderToSend = groupDisplayOrder
		}
		body := map[string]any{
			"group_order":   groupOrderToSend,
			"display_order": displayOrderToSend,
		}
		if groupUngroup {
			body["group_name"] = nil
		} else {
			body["group_name"] = groupName
		}
		var updated containerView
		if _, err := client.do("PUT", pathf("/api/containers/%s/group", c.ID), nil, body, &updated); err != nil {
			return err
		}
		return renderContainer(updated)
	},
}

var containerUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Manage in-progress container updates",
}

var containerUpdateStatusCmd = &cobra.Command{
	Use:   "status [id|name]",
	Short: "Show the status of an in-progress update",
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
		var raw json.RawMessage
		if _, err := client.do("GET", pathf("/api/containers/%s/update", c.ID), nil, nil, &raw); err != nil {
			return err
		}
		os.Stdout.Write(prettyJSON(raw))
		fmt.Println()
		return nil
	},
}

var containerUpdateAcceptCmd = &cobra.Command{
	Use:   "accept [id|name]",
	Short: "Promote a ready staged update",
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
		var updated containerView
		if _, err := client.do("POST", pathf("/api/containers/%s/update/accept", c.ID), nil, nil, &updated); err != nil {
			return err
		}
		return renderContainer(updated)
	},
}

var containerUpdateCancelCmd = &cobra.Command{
	Use:   "cancel [id|name]",
	Short: "Cancel an in-progress update",
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
		if _, err := client.do("POST", pathf("/api/containers/%s/update/cancel", c.ID), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Cancelled in-progress update on %s\n", c.Name)
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

// resolveContainer accepts either a UUID or a name. When given a name,
// list containers and pick the one with a matching name. If both a debug
// and a non-debug container share the name, --debug-mode disambiguates.
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
		if c.Name != id {
			continue
		}
		if useDebugFilter && c.Debug != containerDebugSelector {
			continue
		}
		matches = append(matches, c)
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no container named %q (use the container ID or `tinfoil container list`)", id)
	case 1:
		c := matches[0]
		return &c, nil
	default:
		return nil, fmt.Errorf("multiple containers named %q (debug + non-debug); pass --debug-mode or use the container ID", id)
	}
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

// buildLifecycleBody assembles the request body shared by /start and
// /relaunch. Only fields whose flag was set on the command line are included
// so the controlplane keeps the existing values for the rest.
func buildLifecycleBody(cmd *cobra.Command,
	tag string,
	variables, secrets, sshKeys []string,
	debug, staging, customDomain, host string,
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
	if cmd.Flags().Changed("staging") {
		v, err := parseTriBool(staging)
		if err != nil {
			return nil, fmt.Errorf("--staging: %w", err)
		}
		body["staging"] = v
	}
	if cmd.Flags().Changed("custom-domain") {
		body["custom_domain"] = customDomain
	}
	if cmd.Flags().Changed("host") {
		body["host_name"] = host
	}
	if len(body) == 0 {
		return nil, nil
	}
	return body, nil
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
	if outputFormat == "json" {
		return printJSON(c)
	}
	fmt.Printf("ID:           %s\n", c.ID)
	fmt.Printf("Name:         %s\n", c.Name)
	fmt.Printf("Status:       %s\n", c.Status)
	fmt.Printf("Repo:         %s@%s\n", c.Repo, c.CurrentTag)
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
	if c.Debug {
		fmt.Printf("Mode:         debug\n")
	}
	if c.Staging {
		fmt.Printf("Mode:         staging\n")
	}
	if c.AutoUpdate {
		fmt.Printf("Auto-update:  enabled\n")
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
	if c.UpdateTag != "" {
		state := c.UpdateStatus
		if c.UpdateType != "" {
			state = state + "/" + c.UpdateType
		}
		fmt.Printf("In-progress:  %s (%s)\n", c.UpdateTag, state)
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
			truncate(c.Name, 24), c.Status, truncate(domain, 30), truncate(tag, 10), c.Repo,
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

