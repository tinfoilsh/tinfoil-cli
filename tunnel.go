package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
)

var (
	forwardPorts    []string
	forwardStdio    uint
	forwardSealedTo string
	tunnelAPIKey    string
	allowDebug      bool
)

func addTunnelFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&tunnelAPIKey, "api-key", "", "API key (tk_...) for the tunnel (default $"+envTunnelAPIKey+")")
	cmd.Flags().BoolVar(&allowDebug, "allow-debug", false, "Allow debug-mode enclaves, which have a shell inside")
	addTrustDangerousFlag(cmd)
}

// enclaveAPIKey is the key the shim's tunnel handler validates. It goes to the
// enclave rather than the controlplane, so it never comes from the saved login.
// It has its own env var because TINFOIL_API_KEY overrides the admin login and
// would break the controlplane lookup that resolves a container name.
func enclaveAPIKey() string {
	if key := strings.TrimSpace(tunnelAPIKey); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv(envTunnelAPIKey))
}

func newForwardCommand() *cobra.Command {
	forwardCmd := &cobra.Command{
		Use:   "forward [container|hostname]",
		Short: "Forward local TCP ports into a verified enclave",
		Long: `Only ports the deployment publishes in tinfoil-config.yml can be forwarded.
A hostname target needs --repo or --config to select the expected workload.`,
		Example: `  Forward one port
  tinfoil forward my-server -L 25565:25565

  Forward several ports
  tinfoil forward my-server -L 5432:5432 -L 8080:8080

  Forward to an enclave hostname, verified against a repo
  tinfoil forward enclave.example.com --repo org/workload -L 2022:2022

  Verify against a local config file
  tinfoil forward my-server --config tinfoil-config.yml -L 8080:8080`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(forwardPorts) == 0) == (forwardStdio == 0) {
				return fmt.Errorf("pass either -L <local-port>:<enclave-port> or --stdio <enclave-port>")
			}
			if forwardStdio > 65535 {
				return fmt.Errorf("invalid --stdio port %d: must be 1..65535", forwardStdio)
			}

			// Parse every forward before binding anything, so a bad spec leaves
			// nothing listening.
			specs := make([]connection.ForwardSpec, 0, len(forwardPorts))
			for _, raw := range forwardPorts {
				spec, err := connection.ParseForwardSpec(raw)
				if err != nil {
					return err
				}
				specs = append(specs, spec)
			}

			var identifier string
			if len(args) == 1 {
				identifier = args[0]
			}
			target, err := resolveTunnelTarget(identifier)
			if err != nil {
				return err
			}
			tun, err := newTunnel(target)
			if err != nil {
				return err
			}

			if forwardStdio != 0 {
				stream, err := tun.Dial(int(forwardStdio))
				if err != nil {
					return err
				}
				if err := connection.Splice(stdioConn{}, stream); err != nil {
					return fmt.Errorf("tunnel to %s port %d: %w", target.host, forwardStdio, err)
				}
				return nil
			}
			return connection.ListenAndForward(tun, specs, func(address net.Addr, remote int) {
				fmt.Printf("Forwarding %s -> %s port %d\n", address, target.host, remote)
			})
		},
	}
	forwardCmd.Flags().StringArrayVarP(&forwardPorts, "local", "L", nil, "Forward [bind:]<local-port>:<enclave-port>; may be repeated")
	forwardCmd.Flags().UintVar(&forwardStdio, "stdio", 0, "Pipe a single stream to <enclave-port> over stdin/stdout instead of listening")
	forwardCmd.Flags().StringVar(&forwardSealedTo, "sealed-to", "", "RTMR3 the enclave must carry")
	forwardCmd.Flags().MarkHidden("sealed-to")
	addTunnelFlags(forwardCmd)
	return forwardCmd
}

// tunnelTarget is the enclave a tunnel connects to, plus what a container
// lookup recorded for it.
type tunnelTarget struct {
	workload  *workloadTarget
	container *containerView
	name      string
	host      string
	repo      string
	sshPort   int
	debug     bool
	// sealedTo is the RTMR3 the enclave must carry, for a caller that knows what
	// this boot was sealed to. Empty requires an unextended register.
	sealedTo string
}

// resolveTunnelTarget accepts an enclave hostname, a container name, or a
// container ID. A dotted identifier is a hostname: dev-launched and sandbox
// CVMs answer on one but have no controlplane record.
func resolveTunnelTarget(identifier string) (*tunnelTarget, error) {
	if identifier == "" {
		identifier = enclaveHost
	}
	if identifier == "" {
		return nil, fmt.Errorf("name a container or an enclave hostname, or pass --enclave")
	}
	if strings.Contains(identifier, ".") {
		return &tunnelTarget{name: identifier, host: identifier, repo: repo, sealedTo: forwardSealedTo}, nil
	}

	cp, err := authedClient()
	if err != nil {
		return nil, err
	}
	container, err := resolveContainer(cp, identifier)
	if err != nil {
		return nil, err
	}
	if container.Repo == defaultSandboxRepo {
		if container.Volumes == nil {
			id := container.ID
			if container, err = resolveContainerDetail(cp, id); err != nil {
				return nil, err
			}
			if container.ID != id {
				return nil, errors.New("sandbox resource changed while resolving it")
			}
		}
		target, err := resolveWorkload(*container, defaultSandboxRepo, repo)
		if err != nil {
			return nil, err
		}
		return &tunnelTarget{container: &target.containerView, workload: target, name: target.Name,
			host: target.Domain, repo: target.source, sshPort: target.SSHPort, sealedTo: forwardSealedTo}, nil
	}
	original := *container
	host := strings.TrimSpace(container.Domain)
	if host == "" {
		host = strings.TrimSpace(container.InternalDomain)
	}
	if host == "" {
		return nil, fmt.Errorf("container %s has no domain (status=%s) — cannot tunnel", container.Name, container.Status)
	}
	override := repo
	if repo != "" && !strings.Contains(repo, "/") {
		// A bare org is a valid assertion here but not a verifier pin:
		// tinfoil-go's reference grammar requires owner/name — it has no
		// org-prefix match, even though the endorsed name it compares against
		// would support one. Until the SDK grows that, assertTrustedSource
		// checks the org against the resolved name (which the verifier then
		// proves via the signed name→digest endorsement, backstopping the
		// string check), and the verifier pins the resolved reference.
		override = ""
	}
	if override != "" {
		container.Repo = override
	}
	if container.Source == containerSourceLocal && repo != "" {
		return nil, fmt.Errorf("local containers require --config instead of --repo")
	}
	if container.ConfigName != "" || container.Source == containerSourceLocal {
		connection, err := containerConnection(*container, false, override)
		if err != nil {
			return nil, err
		}
		container.Repo = connection.source
		host = connection.host
		if container.Source == containerSourceLocal {
			if err := checkLocalConfigDigest(connection.ConfigDigest); err != nil {
				return nil, err
			}
		}
	}
	if container.Repo == "" && container.Source != containerSourceLocal {
		return nil, fmt.Errorf("container %s has no repo recorded — cannot tunnel", container.Name)
	}
	if container.Source == containerSourceLocal {
		// A local config is a caller-held expectation: the file's digest is
		// the trust decision, so the connection policy does not apply.
	} else if err := trustConnectionSource(container.Repo, repo); err != nil {
		return nil, err
	}
	return &tunnelTarget{
		container: &original,
		name:      container.Name,
		host:      host,
		repo:      container.Repo,
		sshPort:   container.SSHPort,
		debug:     container.Debug,
		sealedTo:  forwardSealedTo,
	}, nil
}

// Streaming bodies are not replayable, so key-error retries stay disabled.
func newTunnel(target *tunnelTarget) (*connection.Tunnel, error) {
	input, err := verificationInput(target.repo, target.sealedTo)
	if err != nil {
		return nil, err
	}
	return connection.NewTunnel(context.Background(), target.host, input, connection.TunnelOptions{
		APIKey: enclaveAPIKey(), Debug: target.debug, AllowDebug: allowDebug,
	})
}

// stdioConn presents this process's stdin/stdout as one connection, so --stdio
// can serve as an ssh ProxyCommand.
type stdioConn struct{}

func (stdioConn) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdioConn) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdioConn) Close() error                { return os.Stdout.Close() }
