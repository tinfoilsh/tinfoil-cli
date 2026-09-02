package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// debugToolboxContainer is the container tinfoild injects for debug mode
// (tinfoil-config's ReservedDebugContainerName).
const debugToolboxContainer = "tinfoil-debug-toolbox"

var (
	forwardPorts []string
	forwardStdio uint
	tunnelAPIKey string
	allowDebug   bool
)

func init() {
	rootCmd.AddCommand(forwardCmd)
	forwardCmd.Flags().StringArrayVarP(&forwardPorts, "local", "L", nil, "Forward [bind:]<local-port>:<enclave-port>; may be repeated")
	forwardCmd.Flags().UintVar(&forwardStdio, "stdio", 0, "Pipe a single stream to <enclave-port> over stdin/stdout instead of listening")
	addTunnelFlags(forwardCmd)
	forwardCmd.SilenceUsage = true
}

func addTunnelFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&tunnelAPIKey, "api-key", "", "API key the enclave validates for tunnels (default $"+envAPIKey+")")
	cmd.Flags().BoolVar(&allowDebug, "allow-debug", false, "Tunnel into an enclave running in debug mode, which has a shell inside it")
}

// enclaveAPIKey is the key the shim's tunnel handler validates. It goes to the
// enclave rather than the controlplane, so it never comes from the saved login.
func enclaveAPIKey() string {
	if key := strings.TrimSpace(tunnelAPIKey); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv(envAPIKey))
}

var forwardCmd = &cobra.Command{
	Use:   "forward [container|hostname]",
	Short: "Forward local TCP ports into a verified enclave",
	Long: `Tunnel raw TCP into an enclave over its attested TLS connection.

The enclave's shim accepts a tunnel only to a port one of its containers
publishes in tinfoil-config.yml, so a forward reaches exactly what the
deployment declared and nothing else.

The target is a container name, whose domain and repo are looked up through the
controlplane, or an enclave hostname (anything containing a dot), which needs no
controlplane record. A hostname without --repo is attested as genuine
confidential-computing hardware, but its measurement is checked against no
release.

  tinfoil forward my-server -L 25565:25565
  tinfoil forward my-server -L 5432:5432 -L 8080:8080
  tinfoil forward otter-4s7ut6c3.box2.tinfoil.sh -L 2022:2022`,
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
		specs := make([]forwardSpec, 0, len(forwardPorts))
		for _, raw := range forwardPorts {
			spec, err := parseForwardSpec(raw)
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
			stream, err := tun.dial(int(forwardStdio))
			if err != nil {
				return err
			}
			splice(stdioConn{}, stream)
			return nil
		}
		return listenAndForward(tun, specs)
	},
}

type forwardSpec struct {
	bind   string
	local  int
	remote int
}

func parseForwardSpec(raw string) (forwardSpec, error) {
	spec := forwardSpec{bind: "127.0.0.1"}
	fields := strings.Split(raw, ":")
	if len(fields) == 3 {
		spec.bind, fields = fields[0], fields[1:]
		if spec.bind == "" {
			return spec, fmt.Errorf("invalid forward %q: empty bind address; drop it to listen on 127.0.0.1, or name 0.0.0.0 to listen on every interface", raw)
		}
	}
	if len(fields) != 2 {
		return spec, fmt.Errorf("invalid forward %q: want [bind:]<local-port>:<enclave-port>", raw)
	}
	for i, into := range []*int{&spec.local, &spec.remote} {
		port, err := strconv.Atoi(fields[i])
		if err != nil || port < 1 || port > 65535 {
			return spec, fmt.Errorf("invalid forward %q: port %q must be 1..65535", raw, fields[i])
		}
		*into = port
	}
	return spec, nil
}

func listenAndForward(tun *tunnel, specs []forwardSpec) error {
	failed := make(chan error, len(specs))
	for _, spec := range specs {
		listener, err := net.Listen("tcp", net.JoinHostPort(spec.bind, strconv.Itoa(spec.local)))
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Printf("Forwarding %s -> %s port %d\n", listener.Addr(), tun.host, spec.remote)

		go func() {
			for {
				local, err := listener.Accept()
				if err != nil {
					failed <- err
					return
				}
				go func() {
					stream, err := tun.dial(spec.remote)
					if err != nil {
						log.WithError(err).Error("opening tunnel")
						local.Close()
						return
					}
					splice(local, stream)
				}()
			}
		}()
	}
	return <-failed
}

// tunnelTarget is the enclave a tunnel connects to, plus what a container
// lookup recorded for it.
type tunnelTarget struct {
	name    string
	host    string
	repo    string
	sshPort int
	debug   bool
}

// resolveTunnelTarget accepts an enclave hostname, a container name, or a
// container ID. A dotted identifier is a hostname: dev-launched and sandbox
// CVMs answer on one but have no controlplane record.
func resolveTunnelTarget(identifier string) (*tunnelTarget, error) {
	if identifier == "" {
		identifier = enclaveHost
	}
	if identifier == "" {
		return nil, fmt.Errorf("name a container or an enclave hostname, or pass --host")
	}
	if strings.Contains(identifier, ".") {
		return &tunnelTarget{name: identifier, host: identifier, repo: repo}, nil
	}

	cp, err := authedClient()
	if err != nil {
		return nil, err
	}
	container, err := resolveContainer(cp, identifier)
	if err != nil {
		return nil, err
	}
	host := strings.TrimSpace(container.Domain)
	if host == "" {
		host = strings.TrimSpace(container.InternalDomain)
	}
	if host == "" {
		return nil, fmt.Errorf("container %s has no domain (status=%s) — cannot tunnel", container.Name, container.Status)
	}
	if container.Repo == "" {
		return nil, fmt.Errorf("container %s has no repo recorded — cannot tunnel", container.Name)
	}
	return &tunnelTarget{
		name:    container.Name,
		host:    host,
		repo:    container.Repo,
		sshPort: container.SSHPort,
		debug:   container.Debug,
	}, nil
}

// tunnel opens TCP streams inside a verified enclave through the shim's HTTP/2
// CONNECT handler. The enclave is verified once, and every stream then rides a
// connection pinned to the attested certificate.
type tunnel struct {
	transport *http2.Transport
	host      string
	apiKey    string
}

// verifiedTLSFingerprint returns the TLS public key the enclave's attestation
// commits to, for the tunnel to pin. With a repo the measurement is also
// checked against that repo's published sigstore bundle; without one there is
// nothing to compare against, so the check stops at proving the key is held by
// genuine confidential-computing hardware.
func verifiedTLSFingerprint(enclaveHost, repo string) (string, error) {
	log.WithFields(log.Fields{"enclave_host": enclaveHost, "repo": repo}).Info("verifying enclave")

	if repo != "" {
		groundTruth, err := client.NewSecureClient(enclaveHost, repo).Verify()
		if err != nil {
			return "", fmt.Errorf("verifying %s against %s: %w", enclaveHost, repo, err)
		}
		return groundTruth.TLSPublicKey, nil
	}

	document, err := attestation.Fetch(enclaveHost)
	if err != nil {
		return "", fmt.Errorf("fetching attestation from %s: %w", enclaveHost, err)
	}
	verification, err := document.Verify()
	if err != nil {
		return "", fmt.Errorf("verifying attestation from %s: %w", enclaveHost, err)
	}
	log.Warnf("No repo given, so %s runs unverified code on verified hardware; pass --repo to check the measurement against a release", enclaveHost)
	log.Warnf("Enclave measurement: %s", verification.Measurement)
	return verification.TLSPublicKeyFP, nil
}

func newTunnel(target *tunnelTarget) (*tunnel, error) {
	fingerprint, err := verifiedTLSFingerprint(target.host, target.repo)
	if err != nil {
		return nil, err
	}

	host, port, splitErr := net.SplitHostPort(target.host)
	if splitErr != nil {
		host, port = target.host, "443"
	}
	address := net.JoinHostPort(host, port)

	tun := &tunnel{
		host:   host,
		apiKey: enclaveAPIKey(),
		transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				VerifyConnection: func(state tls.ConnectionState) error {
					certFP, err := attestation.ConnectionCertFP(state)
					if err != nil {
						return err
					}
					if certFP != fingerprint {
						return client.ErrCertMismatch
					}
					return nil
				},
			},
			// The request authority carries the enclave-side port, so the
			// address http2 derives from it is never the one to dial.
			DialTLSContext: func(ctx context.Context, network, _ string, config *tls.Config) (net.Conn, error) {
				return (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
			},
		},
	}
	if err := checkDebugMode(tun, target); err != nil {
		return nil, err
	}
	return tun, nil
}

// checkDebugMode refuses a tunnel into an enclave running the debug toolbox,
// which gives anyone holding an injected SSH key a shell next to the workload.
// Debug mode is a measured boot flag, so --repo already rejects one; this covers
// the repo-less path, where the enclave's container list is all there is to go on.
func checkDebugMode(tun *tunnel, target *tunnelTarget) error {
	debug, err := target.debug, error(nil)
	if !debug {
		debug, err = tun.runsDebugToolbox()
	}

	var finding string
	switch {
	case debug:
		finding = fmt.Sprintf("%s runs in debug mode", target.host)
	case err != nil:
		finding = fmt.Sprintf("cannot tell whether %s runs in debug mode (%v)", target.host, err)
	default:
		return nil
	}

	if !allowDebug {
		return fmt.Errorf("%s: %s puts an interactive shell inside the enclave, so its confidentiality guarantees do not hold. Pass --allow-debug to tunnel in anyway",
			finding, debugToolboxContainer)
	}
	log.Warnf("%s: anyone holding an injected SSH key has a shell inside the enclave", finding)
	return nil
}

// runsDebugToolbox asks the enclave which containers it runs. The answer comes
// over the pinned connection, so it is authentic to the attested enclave.
func (t *tunnel) runsDebugToolbox() (bool, error) {
	resp, err := (&http.Client{Transport: t.transport}).Get("https://" + t.host + "/.well-known/tinfoil-containers")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET /.well-known/tinfoil-containers: %s", resp.Status)
	}

	var status struct {
		Containers []struct {
			Name string `json:"name"`
		} `json:"containers"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status); err != nil {
		return false, fmt.Errorf("decoding container status: %w", err)
	}
	for _, container := range status.Containers {
		if container.Name == debugToolboxContainer {
			return true, nil
		}
	}
	return false, nil
}

func (t *tunnel) dial(port int) (tunnelStream, error) {
	authority := net.JoinHostPort(t.host, strconv.Itoa(port))
	header := http.Header{}
	if t.apiKey != "" {
		header.Set("Authorization", "Bearer "+t.apiKey)
	}

	body, writer := io.Pipe()
	resp, err := t.transport.RoundTrip(&http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Scheme: "https", Host: authority},
		Host:       authority,
		Header:     header,
		Body:       body,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	})
	if err != nil {
		writer.Close()
		return tunnelStream{}, fmt.Errorf("CONNECT %s: %w", authority, err)
	}
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		writer.Close()
		return tunnelStream{}, fmt.Errorf("CONNECT %s: %s: %s", authority, resp.Status, strings.TrimSpace(string(detail)))
	}
	return tunnelStream{body: resp.Body, writer: writer}, nil
}

// tunnelStream is the client end of a CONNECT stream: the response body reads,
// the request body writes.
type tunnelStream struct {
	body   io.ReadCloser
	writer *io.PipeWriter
}

func (s tunnelStream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s tunnelStream) Write(p []byte) (int, error) { return s.writer.Write(p) }

func (s tunnelStream) Close() error {
	s.writer.Close()
	return s.body.Close()
}

// splice pumps a local connection through a tunnel stream. Ending the request
// body on a local half-close lets replies still in flight arrive.
func splice(local io.ReadWriteCloser, stream tunnelStream) {
	go func() {
		_, _ = io.Copy(stream, local)
		stream.writer.Close()
	}()
	_, _ = io.Copy(local, stream)
	local.Close()
	stream.Close()
}

// stdioConn presents this process's stdin/stdout as one connection, so --stdio
// can serve as an ssh ProxyCommand.
type stdioConn struct{}

func (stdioConn) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdioConn) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdioConn) Close() error                { return os.Stdout.Close() }
