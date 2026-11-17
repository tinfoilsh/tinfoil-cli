package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
)

type containerDestination = controlplane.Destination

const (
	networkEgressRestricted         = "restricted"
	networkEgressUnrestricted       = "unrestricted"
	networkProtocolTCP              = "tcp"
	networkProtocolUDP              = "udp"
	networkDestinationMinPrefixBits = 16
	networkPolicyPending            = "pending"
	networkPolicyUnknown            = "unknown"
	networkPolicyStopped            = "stopped"
)

var networkPolicyFlags = []string{"public", "private", "egress", "allow", "allow-container", "remove", "remove-container"}

type containerNetworkDetails struct {
	DesiredPolicy *containerNetworkPolicy `json:"desired_policy"`
	Status        string                  `json:"policy_status"`
	Error         string                  `json:"error,omitempty"`
}

func newContainerNetworkCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	networkCmd := &cobra.Command{
		Use:   "network",
		Short: "Show or change which networks a container can reach",
	}
	networkCmd.AddCommand(&cobra.Command{
		Use:   "get [id|name]",
		Short: "Show a container's network policy and whether it is applied",
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
			var raw json.RawMessage
			if _, err := client.do("GET", pathf("/api/containers/%s/network", c.ID), nil, nil, &raw); err != nil {
				return err
			}
			return renderContainerNetwork(commandStreams(cmd), outputOpts, client, *c, raw)
		},
	})
	opts := &networkPolicyOptions{}
	setCmd := &cobra.Command{
		Use:   "set [id|name]",
		Short: "Change a container's network policy",
		Long: `Changes apply on top of the saved policy. A container without a saved policy
starts from public inbound access and unrestricted egress.`,
		Example: `  Allow only HTTPS to one range and SSH to another container
  tinfoil container network set app --egress restricted --allow 192.200.0.0/24:443=controlplane.tailscale.com --allow-container db:22

  Stop accepting traffic from the internet
  tinfoil container network set app --private`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.ContainsFunc(networkPolicyFlags, cmd.Flags().Changed) {
				return fmt.Errorf("nothing to change; see --help")
			}
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			c, err := resolveContainer(client, args[0])
			if err != nil {
				return err
			}
			var current containerNetworkDetails
			if _, err := client.do("GET", pathf("/api/containers/%s/network", c.ID), nil, nil, &current); err != nil {
				return err
			}
			policy := containerNetworkPolicy{Public: true, EgressMode: networkEgressUnrestricted}
			if current.DesiredPolicy != nil {
				policy = *current.DesiredPolicy
			}
			if policy.EgressMode == "" {
				policy.EgressMode = networkEgressRestricted
			}
			if err := opts.apply(client, &policy); err != nil {
				return err
			}
			var raw json.RawMessage
			_, err = client.do("PUT", pathf("/api/containers/%s/network", c.ID), nil, policy, &raw)
			var apiErr *controlplane.Error
			if errors.As(err, &apiErr) {
				var details containerNetworkDetails
				if json.Unmarshal(apiErr.Body, &details) != nil || details.Status == "" {
					return err
				}
				raw = apiErr.Body
			}
			if renderErr := renderContainerNetwork(commandStreams(cmd), outputOpts, client, *c, raw); renderErr != nil {
				return renderErr
			}
			return err
		},
	}
	addNetworkPolicyFlags(setCmd, opts)
	setCmd.Flags().StringArrayVar(&opts.removeContainers, "remove-container", nil, "Remove access to a container, as <name|id>[:<port>]; may be repeated")
	setCmd.Flags().StringArrayVar(&opts.remove, "remove", nil, "Remove a destination, as <cidr>[/tcp|/udp]:<port>; may be repeated")
	networkCmd.AddCommand(setCmd)
	return networkCmd
}

func addNetworkPolicyFlags(cmd *cobra.Command, opts *networkPolicyOptions) {
	cmd.Flags().BoolVar(&opts.public, "public", false, "Accept inbound traffic from the internet")
	cmd.Flags().BoolVar(&opts.private, "private", false, "Stop accepting inbound traffic from the internet")
	cmd.MarkFlagsMutuallyExclusive("public", "private")
	cmd.Flags().StringVar(&opts.egress, "egress", "", "Outbound access: restricted (only allowed containers and destinations) or unrestricted")
	cmd.Flags().StringArrayVar(&opts.allowContainers, "allow-container", nil, "Allow connections to a container you own, as <name|id>:<port>; may be repeated")
	cmd.Flags().StringArrayVar(&opts.allow, "allow", nil, "Allow a public IPv4 destination, as <cidr>[/tcp|/udp]:<port>[=<hostname>] (default tcp; the hostname resolves only to addresses in the range); may be repeated")
}

func (opts *networkPolicyOptions) apply(client *cpClient, policy *containerNetworkPolicy) error {
	if opts.public || opts.private {
		policy.Public = opts.public
	}
	if opts.egress != "" {
		if opts.egress != networkEgressRestricted && opts.egress != networkEgressUnrestricted {
			return fmt.Errorf("--egress must be %s or %s", networkEgressRestricted, networkEgressUnrestricted)
		}
		policy.EgressMode = opts.egress
	}
	for _, raw := range opts.removeContainers {
		ref, port, err := parseContainerPort(raw, false)
		if err != nil {
			return fmt.Errorf("--remove-container: %w", err)
		}
		peer, err := resolveContainer(client, ref)
		if err != nil {
			return err
		}
		before := len(policy.Egress)
		if policy.Egress = slices.DeleteFunc(policy.Egress, func(p containerPeer) bool {
			return p.ContainerID == peer.ID && (port == 0 || p.Port == port)
		}); len(policy.Egress) == before {
			return fmt.Errorf("--remove-container %q matches no allowed container", raw)
		}
	}
	for _, raw := range opts.remove {
		d, err := parseNetworkDestination(raw)
		if err != nil {
			return fmt.Errorf("--remove: %w", err)
		}
		before := len(policy.Destinations)
		if policy.Destinations = slices.DeleteFunc(policy.Destinations, d.sameRule); len(policy.Destinations) == before {
			return fmt.Errorf("--remove %q matches no allowed destination", raw)
		}
	}
	for _, raw := range opts.allowContainers {
		ref, port, err := parseContainerPort(raw, true)
		if err != nil {
			return fmt.Errorf("--allow-container: %w", err)
		}
		peer, err := resolveContainer(client, ref)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(policy.Egress, func(p containerPeer) bool { return p.ContainerID == peer.ID && p.Port == port }) {
			policy.Egress = append(policy.Egress, containerPeer{ContainerID: peer.ID, Port: port})
		}
	}
	for _, raw := range opts.allow {
		d, err := parseNetworkDestination(raw)
		if err != nil {
			return fmt.Errorf("--allow: %w", err)
		}
		policy.Destinations = append(slices.DeleteFunc(policy.Destinations, d.sameRule), containerDestination(d))
	}
	return nil
}

type networkDestination containerDestination

func (d networkDestination) sameRule(other containerDestination) bool {
	return d.CIDR == other.CIDR && d.Protocol == other.Protocol && d.Port == other.Port
}

func parseNetworkDestination(raw string) (networkDestination, error) {
	rule, name, _ := strings.Cut(raw, "=")
	target, portText, ok := strings.Cut(rule, ":")
	if !ok {
		return networkDestination{}, fmt.Errorf("%q: expected <cidr>[/tcp|/udp]:<port>[=<hostname>]", raw)
	}
	protocol := networkProtocolTCP
	if i := strings.LastIndex(target, "/"); strings.Count(target, "/") == 2 {
		target, protocol = target[:i], target[i+1:]
	}
	if protocol != networkProtocolTCP && protocol != networkProtocolUDP {
		return networkDestination{}, fmt.Errorf("%q: protocol must be %s or %s", raw, networkProtocolTCP, networkProtocolUDP)
	}
	prefix, err := netip.ParsePrefix(target)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < networkDestinationMinPrefixBits || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
		return networkDestination{}, fmt.Errorf("%q: %q must be a public IPv4 range of /%d or narrower with its host bits zero", raw, target, networkDestinationMinPrefixBits)
	}
	port, err := parseNetworkPort(portText)
	if err != nil {
		return networkDestination{}, fmt.Errorf("%q: %w", raw, err)
	}
	return networkDestination{Name: name, CIDR: prefix.String(), Protocol: protocol, Port: port}, nil
}

func parseContainerPort(raw string, portRequired bool) (string, int, error) {
	ref, portText, ok := strings.Cut(raw, ":")
	if !ok && !portRequired {
		return ref, 0, nil
	}
	if !ok {
		return "", 0, fmt.Errorf("%q: expected <name|id>:<port>", raw)
	}
	port, err := parseNetworkPort(portText)
	if err != nil {
		return "", 0, fmt.Errorf("%q: %w", raw, err)
	}
	return ref, port, nil
}

func parseNetworkPort(text string) (int, error) {
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > maxConnectionPort {
		return 0, fmt.Errorf("port must be between 1 and %d", maxConnectionPort)
	}
	return port, nil
}

func renderContainerNetwork(streams commandIO, outputOpts *outputOptions, client *cpClient, c containerView, raw json.RawMessage) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, raw)
	}
	var details containerNetworkDetails
	if err := json.Unmarshal(raw, &details); err != nil {
		return fmt.Errorf("decoding network policy: %w", err)
	}
	policy, source := details.DesiredPolicy, ""
	if policy == nil {
		policy, source = &containerNetworkPolicy{Public: true, EgressMode: networkEgressUnrestricted}, " (default)"
	}
	inbound := "private"
	if policy.Public {
		inbound = "public"
	}
	egress := policy.EgressMode
	if egress == "" {
		egress = networkEgressRestricted
	}
	fmt.Fprintf(streams.out, "Inbound:      %s%s\n", inbound, source)
	fmt.Fprintf(streams.out, "Egress:       %s%s\n", egress, source)
	names := map[string]string{}
	if len(policy.Egress) > 0 {
		var list []containerView
		if _, err := client.do("GET", "/api/containers", nil, nil, &list); err == nil {
			for _, row := range list {
				names[row.ID] = row.Name
			}
		}
	}
	label := "Containers:   "
	for _, peer := range policy.Egress {
		name := peer.ContainerID
		if names[peer.ContainerID] != "" {
			name = fmt.Sprintf("%s (%s)", names[peer.ContainerID], peer.ContainerID)
		}
		alias := ""
		if peer.Alias != nil {
			alias = fmt.Sprintf(" via %s:%d", peer.Alias.IP, peer.Alias.Port)
		}
		fmt.Fprintf(streams.out, "%s%s port %d%s\n", label, name, peer.Port, alias)
		label = strings.Repeat(" ", len(label))
	}
	label = "Destinations: "
	for _, d := range policy.Destinations {
		fmt.Fprintln(streams.out, strings.TrimSpace(fmt.Sprintf("%s%s %s:%d %s", label, d.CIDR, d.Protocol, d.Port, d.Name)))
		label = strings.Repeat(" ", len(label))
	}
	fmt.Fprintf(streams.out, "Status:       %s\n", details.Status)
	if details.Error != "" {
		fmt.Fprintf(streams.out, "Error:        %s\n", details.Error)
	}
	switch details.Status {
	case networkPolicyPending, networkPolicyUnknown:
		fmt.Fprintf(streams.out, "Run \"tinfoil container network get %s\" to check whether the policy is applied.\n", c.Name)
	case networkPolicyStopped:
		fmt.Fprintf(streams.out, "The policy applies when %s next starts.\n", c.Name)
	}
	return nil
}
