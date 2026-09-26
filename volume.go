package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type volumeView struct {
	ID            string `json:"id"`
	OrgID         string `json:"clerk_org_id"`
	HostID        string `json:"host_id"`
	HostName      string `json:"host_name"`
	Name          string `json:"name"`
	Image         string `json:"image"`
	SizeBytes     int64  `json:"size_bytes"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Slot          string `json:"slot,omitempty"`
	CreatedAt     string `json:"created_at"`
}

type volumeList struct {
	Volumes        []volumeView `json:"volumes"`
	AllocatedBytes int64        `json:"allocated_storage_bytes"`
	MaxBytes       int64        `json:"max_storage_bytes"`
	AvailableBytes int64        `json:"available_storage_bytes"`
}

// volumeSlot is a volume declared in tinfoil-config.yml. A key secret marks
// the slot as required at deploy.
type volumeSlot struct {
	Name      string `json:"name"`
	KeySecret string `json:"key_secret,omitempty"`
}

// volumeRequest is one --volume value: the volume and, optionally, the
// declared slot it fills.
type volumeRequest struct {
	identifier string
	slot       string
}

var (
	volumeCreateSize string
	volumeCreateHost string
	volumeRenameName string
	volumeAttachAs   string
	volumeYes        bool
)

func init() {
	rootCmd.AddCommand(volumeCmd)
	volumeCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	volumeCmd.AddCommand(volumeListCmd, volumeGetCmd, volumeCreateCmd, volumeRenameCmd, volumeAttachCmd, volumeDetachCmd, volumeDeleteCmd)

	volumeCreateCmd.Flags().StringVar(&volumeCreateSize, "size", "", "Volume size, e.g. 16TiB or 30GiB [required]")
	volumeCreateCmd.Flags().StringVar(&volumeCreateHost, "host", "", "Host to store the volume on (see 'tinfoil container hosts'); required unless only one host is available")
	_ = volumeCreateCmd.MarkFlagRequired("size")
	volumeRenameCmd.Flags().StringVar(&volumeRenameName, "name", "", "New volume name [required]")
	_ = volumeRenameCmd.MarkFlagRequired("name")
	volumeAttachCmd.Flags().StringVar(&volumeAttachAs, "as", "", "Mount name declared in tinfoil-config.yml (defaults to the only declared mount)")
	volumeDeleteCmd.Flags().BoolVar(&volumeYes, "yes", false, "Skip interactive confirmation")
	silenceUsageRecursive(volumeCmd)
}

var volumeCmd = &cobra.Command{
	Use:          "volume",
	Aliases:      []string{"volumes"},
	Short:        "Manage persistent volumes for containers",
	SilenceUsage: true,
}

var volumeListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List volumes in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if _, err := client.do("GET", "/api/volumes", nil, nil, &raw); err != nil {
			return err
		}
		if outputFormat == "json" {
			os.Stdout.Write(prettyJSON(raw))
			fmt.Println()
			return nil
		}
		var list volumeList
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("decoding volumes: %w", err)
		}
		return renderVolumes(list)
	},
}

var volumeGetCmd = &cobra.Command{
	Use:   "get [id|name]",
	Short: "Show a single volume",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		return renderVolume(*v)
	},
}

var volumeCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create an empty volume on a host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		autoUnlock, _ := cmd.Flags().GetBool("auto-unlock")
		if autoUnlock {
			return runAutoUnlockVolumeCreate(cmd, args[0], volumeStorageFactory)
		}
		for _, flag := range []string{"project", "mount", "tag", "domain", "config-file", "config-out", "policy-file", "policy-out"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("--%s requires --auto-unlock", flag)
			}
		}
		size, err := parseSize(volumeCreateSize)
		if err != nil {
			return fmt.Errorf("--size: %w", err)
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		hosts, err := listHosts(client)
		if err != nil {
			return err
		}
		host, err := pickVolumeHost(hosts, volumeCreateHost)
		if err != nil {
			return err
		}
		if volumeCreateHost == "" {
			fmt.Fprintf(os.Stderr, "Using host %s (the only host available).\n", host.Name)
		}
		body := map[string]any{"name": args[0], "host_id": host.ID, "size_bytes": size}
		var created volumeView
		if _, err := client.do("POST", "/api/volumes", nil, body, &created); err != nil {
			return err
		}
		created.HostName = host.Name
		return renderVolume(created)
	},
}

var volumeRenameCmd = &cobra.Command{
	Use:   "rename [id|name]",
	Short: "Rename a volume",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		body := map[string]any{"name": volumeRenameName}
		if _, err := client.do("PATCH", pathf("/api/volumes/%s", v.ID), nil, body, nil); err != nil {
			return err
		}
		fmt.Printf("Renamed volume %s to %s\n", v.Name, volumeRenameName)
		return nil
	},
}

var volumeAttachCmd = &cobra.Command{
	Use:   "attach [volume] [container]",
	Short: "Attach a volume to a stopped container's declared mount",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		c, err := resolveContainerDetail(client, args[1])
		if err != nil {
			return err
		}
		slot, err := declaredSlot(c, volumeAttachAs, "--as")
		if err != nil {
			return err
		}
		if err := attachVolume(client, c.ID, slot, v.ID); err != nil {
			return err
		}
		fmt.Printf("Attached %s to %s as %q\n", v.Name, c.Name, slot)
		printVolumeUnlockGuidance(os.Stdout, c.VolumeSlots)
		return nil
	},
}

var volumeDetachCmd = &cobra.Command{
	Use:   "detach [volume]",
	Short: "Detach a volume from its stopped container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		if v.ContainerID == "" || v.Slot == "" {
			return fmt.Errorf("volume %s is not attached", v.Name)
		}
		if _, err := client.do("DELETE", pathf("/api/containers/%s/volumes/%s", v.ContainerID, v.Slot), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Detached %s from %s\n", v.Name, volumeContainerLabel(*v))
		return nil
	},
}

var volumeDeleteCmd = &cobra.Command{
	Use:     "delete [id|name]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a detached volume and all of its data",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		if v.ContainerID != "" {
			return fmt.Errorf("volume %s is attached to %s; detach it first: tinfoil volume detach %s", v.Name, volumeContainerLabel(*v), args[0])
		}
		fmt.Fprintf(os.Stderr, "Deleting volume %s (%s on %s).\n", v.Name, formatSize(v.SizeBytes), v.HostName)
		fmt.Fprintln(os.Stderr, "This permanently destroys the volume and its data.")
		if err := confirmYes(volumeYes, "deleting a volume"); err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/volumes/%s", v.ID), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted volume %s\n", v.Name)
		return nil
	},
}

func listVolumes(client *cpClient) (volumeList, error) {
	var list volumeList
	if _, err := client.do("GET", "/api/volumes", nil, nil, &list); err != nil {
		return volumeList{}, err
	}
	return list, nil
}

func listHosts(client *cpClient) ([]hostInfo, error) {
	var hosts []hostInfo
	if _, err := client.do("GET", "/api/containers/hosts", nil, nil, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

func attachVolume(client *cpClient, containerID, slot, volumeID string) error {
	body := map[string]any{"volume_id": volumeID}
	_, err := client.do("PUT", pathf("/api/containers/%s/volumes/%s", containerID, slot), nil, body, nil)
	return err
}

// lookupVolume resolves an ID or name against the org's volume list; there is
// no single-volume endpoint.
func lookupVolume(client *cpClient, identifier string) (*volumeView, error) {
	list, err := listVolumes(client)
	if err != nil {
		return nil, err
	}
	return resolveVolume(list.Volumes, identifier)
}

// resolveVolume accepts a volume ID or name. Names are not unique within an
// organization, so a shared name is an error that points at the IDs.
func resolveVolume(volumes []volumeView, identifier string) (*volumeView, error) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return nil, fmt.Errorf("volume identifier is empty")
	}
	if looksLikeUUID(id) {
		for i := range volumes {
			if strings.EqualFold(volumes[i].ID, id) {
				return &volumes[i], nil
			}
		}
	}
	matches := make([]*volumeView, 0, 1)
	for i := range volumes {
		if volumes[i].Name == id {
			matches = append(matches, &volumes[i])
		}
	}
	switch len(matches) {
	case 0:
		if looksLikeUUID(id) {
			return nil, fmt.Errorf("no volume with ID %s (see `tinfoil volume list`)", id)
		}
		return nil, fmt.Errorf("no volume named %q (use the volume ID or `tinfoil volume list`)", id)
	case 1:
		return matches[0], nil
	default:
		lines := make([]string, len(matches))
		for i, v := range matches {
			lines[i] = fmt.Sprintf("  %s  %s on %s", v.ID, formatSize(v.SizeBytes), v.HostName)
		}
		return nil, fmt.Errorf("multiple volumes named %q; use the volume ID:\n%s", id, strings.Join(lines, "\n"))
	}
}

// pickVolumeHost returns the named host, or the only host when no name was
// given.
func pickVolumeHost(hosts []hostInfo, name string) (*hostInfo, error) {
	if name == "" {
		switch len(hosts) {
		case 0:
			return nil, fmt.Errorf("no container hosts are available to this organization")
		case 1:
			return &hosts[0], nil
		}
		names := make([]string, len(hosts))
		for i, h := range hosts {
			names[i] = h.Name
		}
		return nil, fmt.Errorf("--host is required; available hosts: %s", strings.Join(names, ", "))
	}
	for i := range hosts {
		if hosts[i].Name == name {
			return &hosts[i], nil
		}
	}
	return nil, fmt.Errorf("no host named %q (see `tinfoil container hosts`)", name)
}

// parseVolumeRequests reads --volume values of the form
// <id|name>[:<declared name>]. Declared names never contain ':', so the
// split is on the last one.
func parseVolumeRequests(values []string) ([]volumeRequest, error) {
	requests := make([]volumeRequest, 0, len(values))
	for _, raw := range values {
		r := volumeRequest{identifier: strings.TrimSpace(raw)}
		if i := strings.LastIndex(raw, ":"); i >= 0 {
			r.identifier, r.slot = strings.TrimSpace(raw[:i]), strings.TrimSpace(raw[i+1:])
		}
		if r.identifier == "" {
			return nil, fmt.Errorf("invalid --volume %q: expected <id|name>[:<mount name>]", raw)
		}
		if len(values) > 1 && r.slot == "" {
			return nil, fmt.Errorf("--volume %q: use <id|name>:<mount name> when attaching several volumes", raw)
		}
		requests = append(requests, r)
	}
	return requests, nil
}

// resolveVolumeRequests resolves each request to an unattached volume.
func resolveVolumeRequests(all []volumeView, requests []volumeRequest, replacement *containerView) ([]volumeView, error) {
	volumes := make([]volumeView, len(requests))
	seen := map[string]bool{}
	for i, r := range requests {
		v, err := resolveVolume(all, r.identifier)
		if err != nil {
			return nil, err
		}
		if v.ContainerID != "" {
			if replacement == nil || !strings.EqualFold(v.ContainerID, replacement.ID) {
				return nil, fmt.Errorf("volume %s is already attached to %s; only disks attached to the explicit --replace target may be reused", v.Name, volumeContainerLabel(*v))
			}
			if v.HostName != replacement.HostName || v.HostID != replacement.HostID {
				return nil, fmt.Errorf("volume %s does not match replacement target %s's host", v.Name, replacement.ID)
			}
		}
		if seen[v.ID] {
			return nil, fmt.Errorf("volume %s was selected more than once; each mount needs its own disk", v.Name)
		}
		seen[v.ID] = true
		volumes[i] = *v
	}
	return volumes, nil
}

// volumesHost is the host a --volume set implies: every volume must be on it
// and it must agree with --host when that was given.
func volumesHost(volumes []volumeView, flagHost string) (string, error) {
	host := volumes[0].HostName
	for _, v := range volumes[1:] {
		if v.HostName != host || v.HostID != volumes[0].HostID {
			return "", fmt.Errorf("volumes %s (%s) and %s (%s) are on different hosts", volumes[0].Name, host, v.Name, v.HostName)
		}
	}
	if flagHost != "" && flagHost != host {
		return "", fmt.Errorf("--host %s does not match volume %s on host %s", flagHost, volumes[0].Name, host)
	}
	return host, nil
}

// declaredSlot picks the declared volume that want names, or the only one
// when want is empty. how tells the user which flag form selects a slot.
func declaredSlot(c *containerView, want, how string) (string, error) {
	names := make([]string, len(c.VolumeSlots))
	for i, s := range c.VolumeSlots {
		names[i] = s.Name
	}
	if len(names) == 0 {
		return "", fmt.Errorf("container %s declares no mounts in tinfoil-config.yml", c.Name)
	}
	if want == "" {
		if len(names) == 1 {
			return names[0], nil
		}
		return "", fmt.Errorf("container %s declares several mounts (%s); pick one with %s", c.Name, strings.Join(names, ", "), how)
	}
	for _, n := range names {
		if n == want {
			return n, nil
		}
	}
	return "", fmt.Errorf("container %s does not declare mount %q (declared: %s)", c.Name, want, strings.Join(names, ", "))
}

func volumeAssignments(c *containerView, requests []volumeRequest) ([]string, error) {
	mounts := make([]string, len(requests))
	seen := map[string]bool{}
	for i, r := range requests {
		mount, err := declaredSlot(c, r.slot, "<volume>:<mount name>")
		if err != nil {
			return nil, err
		}
		if seen[mount] {
			return nil, fmt.Errorf("mount %q was given twice", mount)
		}
		seen[mount] = true
		mounts[i] = mount
	}
	return mounts, nil
}

// attachVolumes assigns each requested volume to its declared slot on c. It
// stops at the first failure, and the error carries the commands that finish
// the job by hand.
func attachVolumes(client *cpClient, c *containerView, requests []volumeRequest, volumes []volumeView) error {
	slots, err := volumeAssignments(c, requests)
	if err != nil {
		return err
	}
	for i := range requests {
		if err := attachVolume(client, c.ID, slots[i], volumes[i].ID); err != nil {
			return attachRecovery(c, requests[i:], volumes[i].Name, err)
		}
	}
	return nil
}

func attachRecovery(c *containerView, remaining []volumeRequest, volume string, cause error) error {
	var b strings.Builder
	fmt.Fprintf(&b, "could not attach %s: %s. Successful attachments were kept; check container %s's state before retrying:", volume, errMessage(cause), c.ID)
	for _, r := range remaining {
		as := ""
		if r.slot != "" {
			as = " --as " + r.slot
		} else if len(c.VolumeSlots) > 1 {
			as = " --as <mount name>"
		}
		fmt.Fprintf(&b, "\n  tinfoil volume attach %s %s%s", r.identifier, c.ID, as)
	}
	fmt.Fprintf(&b, "\n  %s", deployRecoveryCommand(c))
	return errors.New(b.String())
}

func deployRecoveryCommand(c *containerView) string {
	command := "tinfoil container deploy " + c.ID
	if c.MarkLatestRelease != nil {
		command += fmt.Sprintf(" --mark-latest=%t", *c.MarkLatestRelease)
	}
	return command
}

// withAttachHint appends the attach command when the controlplane refused a
// deploy because a required volume is unattached.
func withAttachHint(err error, c *containerView) error {
	msg := errMessage(err)
	const prefix = "select a volume for required mount "
	if !strings.Contains(msg, prefix) {
		return err
	}
	as := ""
	if len(c.VolumeSlots) > 1 {
		if _, rest, ok := strings.Cut(msg, prefix+`"`); ok {
			if slot, _, ok := strings.Cut(rest, `"`); ok {
				as = " --as " + slot
			}
		}
	}
	return fmt.Errorf("%w\nAttach one first: tinfoil volume attach <volume> %s%s", err, c.Name, as)
}

// loadContainerVolumes returns the volumes attached to c by declared slot,
// or nil when the config declares none.
func loadContainerVolumes(client *cpClient, c containerView) (map[string]volumeView, error) {
	if len(c.VolumeSlots) == 0 {
		return nil, nil
	}
	list, err := listVolumes(client)
	if err != nil {
		return nil, err
	}
	return containerVolumes(c, list.Volumes), nil
}

// containerVolumes maps c's slots to volumes using the container view's own
// assignments when present and the volume rows otherwise; lifecycle responses
// omit the map that the single-container view carries.
func containerVolumes(c containerView, volumes []volumeView) map[string]volumeView {
	attached := make(map[string]volumeView)
	for _, v := range volumes {
		if v.ContainerID == c.ID && v.Slot != "" {
			attached[v.Slot] = v
		}
		for slot, id := range c.Volumes {
			if id == v.ID {
				attached[slot] = v
			}
		}
	}
	return attached
}

// declaredVolumeSlots asks the controlplane to validate repo@tag and returns
// the volume slots its tinfoil-config.yml declares.
func declaredVolumeSlots(client *cpClient, repo, tag, instanceName, replaceID string) ([]volumeSlot, error) {
	var result struct {
		Valid  bool `json:"valid"`
		Errors []struct {
			Field   string `json:"field"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Config *struct {
			Volumes []volumeSlot `json:"volumes"`
		} `json:"config"`
	}
	body := map[string]any{"repo": repo, "tag": tag, "instance_name": instanceName}
	if replaceID != "" {
		body["replace_container_id"] = replaceID
	}
	if _, err := client.do("POST", "/api/containers/validate", nil, body, &result); err != nil {
		var cp *cpError
		if errors.As(err, &cp) && cp.Status == http.StatusForbidden {
			return nil, fmt.Errorf("config validation denied; check the admin key's containers.validate permission for %s: %w", repo, err)
		}
		return nil, fmt.Errorf("validate %s@%s: %w", repo, tag, err)
	}
	if !result.Valid || len(result.Errors) > 0 {
		var message strings.Builder
		fmt.Fprintf(&message, "config validation failed for %s@%s", repo, tag)
		for _, issue := range result.Errors {
			fmt.Fprintf(&message, "\n  %s", issue.Field)
			if issue.Code != "" {
				fmt.Fprintf(&message, " [%s]", issue.Code)
			}
			fmt.Fprintf(&message, ": %s", humanVolumeMessage(issue.Message))
		}
		return nil, errors.New(message.String())
	}
	if result.Config == nil {
		return nil, fmt.Errorf("config validation returned no configuration for %s@%s", repo, tag)
	}
	return result.Config.Volumes, nil
}

// requiredVolumeSlots returns the declared slots the controlplane refuses to
// deploy without a disk: those with a key secret. Slots without one may stay
// empty.
func requiredVolumeSlots(slots []volumeSlot) []volumeSlot {
	var required []volumeSlot
	for _, s := range slots {
		if s.KeySecret != "" {
			required = append(required, s)
		}
	}
	return required
}

// errVolumesRequired explains that the config needs a disk per declared slot
// and lists the commands that create and attach one, so the user never ends
// up with a container that exists but cannot run.
func errVolumesRequired(name string, slots []volumeSlot, host string) error {
	if host == "" {
		host = "<HOST>"
	}
	names := make([]string, len(slots))
	for i, s := range slots {
		names[i] = fmt.Sprintf("%q", s.Name)
	}
	var b strings.Builder
	if len(names) == 1 {
		fmt.Fprintf(&b, "required mount %s has no disk; select an existing disk with --volume or create one:\n", names[0])
	} else {
		fmt.Fprintf(&b, "required mounts %s have no disks; select existing disks with --volume or create them:\n", strings.Join(names, ", "))
	}
	var volumeFlags []string
	for _, s := range slots {
		disk := name + "-" + s.Name
		fmt.Fprintf(&b, "  tinfoil volume create %s --size <SIZE> --host %s\n", disk, host)
		volumeFlags = append(volumeFlags, "--volume "+disk+":"+s.Name)
	}
	fmt.Fprintf(&b, "  tinfoil container create %s ... %s", name, strings.Join(volumeFlags, " "))
	fmt.Fprintln(&b)
	printVolumeUnlockGuidance(&b, slots)
	return fmt.Errorf("%s", b.String())
}

// errMessage is the controlplane's message when err came from it, else the
// error text.
func errMessage(err error) string {
	var cp *cpError
	if errors.As(err, &cp) && cp.Message != "" {
		return humanVolumeMessage(cp.Message)
	}
	return humanVolumeMessage(err.Error())
}

var volumeMessageTerms = strings.NewReplacer(
	"required slot ", "required mount ",
	"config slot", "config mount",
	"volume slot", "volume mount",
	"this slot", "this mount",
	"volume or slot", "volume or mount",
)

func humanVolumeMessage(message string) string {
	return volumeMessageTerms.Replace(message)
}

func volumeContainerLabel(v volumeView) string {
	if v.ContainerName != "" {
		return v.ContainerName
	}
	return v.ContainerID
}

var sizeUnits = map[string]int64{
	"":    1,
	"b":   1,
	"kib": 1 << 10,
	"mib": 1 << 20,
	"gib": 1 << 30,
	"tib": 1 << 40,
	"kb":  1e3,
	"mb":  1e6,
	"gb":  1e9,
	"tb":  1e12,
}

// parseSize reads a byte count with an optional unit: 16TiB, 30 GiB, 1.5TB,
// or plain bytes. Binary units are powers of 1024, decimal ones powers of
// 1000. The controlplane requires a positive multiple of 512.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r == '.') })
	numStr, unitStr := s, ""
	if i >= 0 {
		numStr, unitStr = s[:i], strings.ToLower(strings.TrimSpace(s[i:]))
	}
	num, ok := new(big.Rat).SetString(numStr)
	if numStr == "" || !ok {
		return 0, fmt.Errorf("invalid size %q: expected a number with an optional unit, e.g. 16TiB", s)
	}
	unit, ok := sizeUnits[unitStr]
	if !ok {
		return 0, fmt.Errorf("invalid size %q: units are B, KiB, MiB, GiB, TiB, KB, MB, GB, TB", s)
	}
	num.Mul(num, new(big.Rat).SetInt64(unit))
	if !num.IsInt() || !num.Num().IsInt64() {
		return 0, fmt.Errorf("size %q is not a whole number of bytes", s)
	}
	n := num.Num().Int64()
	if n <= 0 {
		return 0, fmt.Errorf("size %q must be positive", s)
	}
	if n%512 != 0 {
		return 0, fmt.Errorf("size %q must be a multiple of 512 bytes", s)
	}
	return n, nil
}

// formatSize renders bytes in binary units, with one decimal only when the
// value is not whole.
func formatSize(n int64) string {
	units := []struct {
		suffix string
		size   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}}
	for _, u := range units {
		if n < u.size {
			continue
		}
		if n%u.size == 0 {
			return fmt.Sprintf("%d %s", n/u.size, u.suffix)
		}
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/float64(u.size)), ".0") + " " + u.suffix
	}
	return fmt.Sprintf("%d B", n)
}

func renderVolumes(list volumeList) error {
	if len(list.Volumes) == 0 {
		fmt.Println("No volumes.")
	} else {
		fmt.Printf("%-24s  %-10s  %-16s  %-24s  %s\n", "NAME", "SIZE", "HOST", "ATTACHED TO", "CREATED")
		for _, v := range list.Volumes {
			attached := "-"
			if v.ContainerID != "" {
				attached = volumeContainerLabel(v)
			}
			fmt.Printf("%-24s  %-10s  %-16s  %-24s  %s\n",
				truncate(v.Name, 24), formatSize(v.SizeBytes), truncate(v.HostName, 16), truncate(attached, 24), v.CreatedAt,
			)
		}
	}
	fmt.Println()
	fmt.Printf("Storage: %s of %s used, %s available\n", formatSize(list.AllocatedBytes), formatSize(list.MaxBytes), formatSize(list.AvailableBytes))
	return nil
}

func renderVolume(v volumeView) error {
	if outputFormat == "json" {
		return printJSON(v)
	}
	fmt.Printf("Name:         %s\n", v.Name)
	fmt.Printf("ID:           %s\n", v.ID)
	fmt.Printf("Size:         %s\n", formatSize(v.SizeBytes))
	fmt.Printf("Host:         %s\n", v.HostName)
	if v.ContainerID == "" {
		fmt.Printf("Attached to:  not attached\n")
	} else {
		fmt.Printf("Attached to:  %s (as %q)\n", volumeContainerLabel(v), v.Slot)
	}
	fmt.Printf("Created:      %s\n", v.CreatedAt)
	return nil
}
