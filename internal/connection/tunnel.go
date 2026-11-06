package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// debugToolboxContainer is the container tinfoild injects for debug mode
// (tinfoil-config's ReservedDebugContainerName).
const debugToolboxContainer = "tinfoil-debug-toolbox"

const (
	maxContainerStatusBytes = 1 << 20
	maxTunnelErrorBytes     = 512
)

// Tunnel opens TCP streams inside a verified enclave through the shim's HTTP/2
// CONNECT handler. Each new stream requires unexpired v3 verification and rides
// a connection pinned to the endorsed TLS key.
type Tunnel struct {
	transport http.RoundTripper
	host      string
	apiKey    string
}

type TunnelOptions struct {
	APIKey     string
	Debug      bool
	AllowDebug bool
}

// Streaming bodies are not replayable, so key-error retries stay disabled.
func NewTunnel(ctx context.Context, host string, verification Verification, options TunnelOptions) (*Tunnel, error) {
	secure, err := NewClient(ctx, host, verification)
	if err != nil {
		return nil, err
	}
	tun := &Tunnel{host: host, apiKey: options.APIKey, transport: secure.Transport}
	if err := checkDebugMode(tun, options.Debug, options.AllowDebug); err != nil {
		return nil, err
	}
	return tun, nil
}

// checkDebugMode refuses a tunnel into an enclave running the debug toolbox,
// which gives anyone holding an injected SSH key a shell next to the workload.
func checkDebugMode(tun *Tunnel, debug, allowDebug bool) error {
	var err error
	if !debug {
		debug, err = tun.runsDebugToolbox()
	}

	var finding string
	switch {
	case debug:
		finding = fmt.Sprintf("%s runs in debug mode", tun.host)
	case err != nil:
		finding = fmt.Sprintf("cannot tell whether %s runs in debug mode (%v)", tun.host, err)
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
func (t *Tunnel) runsDebugToolbox() (bool, error) {
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxContainerStatusBytes)).Decode(&status); err != nil {
		return false, fmt.Errorf("decoding container status: %w", err)
	}
	for _, container := range status.Containers {
		if container.Name == debugToolboxContainer {
			return true, nil
		}
	}
	return false, nil
}

func (t *Tunnel) Dial(port int) (Stream, error) {
	// The URL selects the attested HTTPS endpoint; CONNECT's authority
	// selects the destination port inside the enclave.
	endpoint := &url.URL{Scheme: "https", Host: t.host}
	authority := net.JoinHostPort(endpoint.Hostname(), strconv.Itoa(port))
	header := http.Header{}
	if t.apiKey != "" {
		header.Set("Authorization", "Bearer "+t.apiKey)
	}

	body, writer := io.Pipe()
	resp, err := t.transport.RoundTrip(&http.Request{
		Method:     http.MethodConnect,
		URL:        endpoint,
		Host:       authority,
		Header:     header,
		Body:       body,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	})
	if err != nil {
		writer.Close()
		return Stream{}, fmt.Errorf("CONNECT %s: %w", authority, err)
	}
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxTunnelErrorBytes))
		resp.Body.Close()
		writer.Close()
		return Stream{}, fmt.Errorf("CONNECT %s: %s: %s", authority, resp.Status, strings.TrimSpace(string(detail)))
	}
	return Stream{body: resp.Body, writer: writer}, nil
}

// Stream is the client end of a CONNECT stream: the response body reads,
// the request body writes.
type Stream struct {
	body   io.ReadCloser
	writer *io.PipeWriter
}

func (s Stream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s Stream) Write(p []byte) (int, error) { return s.writer.Write(p) }

func (s Stream) Close() error {
	s.writer.Close()
	return s.body.Close()
}

// Splice pumps a local connection through a tunnel stream. Ending the request
// body on a local half-close lets replies still in flight arrive.
func Splice(local io.ReadWriteCloser, stream Stream) error {
	go func() {
		_, _ = io.Copy(stream, local)
		stream.writer.Close()
	}()
	_, err := io.Copy(local, stream)
	local.Close()
	stream.Close()
	return err
}
