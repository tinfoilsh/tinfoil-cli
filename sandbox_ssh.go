package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
)

const (
	sandboxAgentKeyName    = "agent_ed25519"
	sandboxBindingName     = "monitor.json"
	sandboxEnrolledKeyName = "enrolled_host_key"

	sandboxAttestationPath     = "/.well-known/tinfoil-attestation"
	maxSandboxAttestationBytes = 32 << 20

	// Monitor routes to a sandbox boot by a name derived from its SSH host key.
	sandboxRouteSuffix = ".sandbox.invalid"
	// Monitor ignores the SSH user; only the device key authorizes routes.
	monitorSSHUser    = "device"
	monitorJumpSuffix = ".monitor"
)

type sandboxBinding struct {
	Scope   accountScope `json:"scope"`
	Monitor string       `json:"monitor"`
}

type sandboxEndpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Resolve the single allowed SSH peer before sending enrollment credentials.
func sandboxPeer(client *cpClient, row containerView) (containerView, sandboxEndpoint, error) {
	var peer containerView
	var network struct {
		Egress []sandboxEndpoint `json:"egress"`
	}
	policy := row.NetworkPolicy
	if policy == nil || policy.EgressMode == "unrestricted" || policy.Public || len(policy.Egress) != 1 || policy.Egress[0].Port != 22 {
		return peer, sandboxEndpoint{}, errors.New("sandbox network policy does not name one SSH peer")
	}
	if _, err := client.do("GET", pathf("/api/containers/%s", policy.Egress[0].ContainerID), nil, nil, &peer); err != nil {
		return peer, sandboxEndpoint{}, err
	}
	if _, err := client.do("GET", pathf("/api/containers/%s/network", row.ID), nil, nil, &network); err != nil {
		return peer, sandboxEndpoint{}, err
	}
	if len(network.Egress) != 1 || !validMonitorEndpoint(network.Egress[0].IP, network.Egress[0].Port) || peer.SSHPort < 1 || peer.SSHPort > maxConnectionPort {
		return peer, sandboxEndpoint{}, errors.New("peer is unavailable")
	}
	return peer, network.Egress[0], nil
}

func validMonitorEndpoint(ip string, port int) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil && port >= 1 && port <= maxConnectionPort
}

// Generate keys only before binding; bound sandboxes must retain their keys.
func sandboxKeysFor(name string, binding sandboxBinding, create bool, credential *ownerCredential) (*sandboxKeys, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	switch err := bindSandbox(dir, binding, false); {
	case err == nil:
		return readSandboxKeys(dir)
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	case !create:
		return nil, fmt.Errorf("this device has no saved Monitor binding for %s", name)
	}
	if err := prepareStorageDirectory(dir); err != nil {
		return nil, err
	}
	if err := saveOwnerCredential(filepath.Join(dir, sandboxDiskKeyName), credential); err != nil {
		return nil, err
	}
	if _, err := ensureSSHKey(filepath.Join(dir, sandboxAgentKeyName)); err != nil {
		return nil, err
	}
	if err := bindSandbox(dir, binding, true); err != nil {
		return nil, err
	}
	return readSandboxKeys(dir)
}

func bindSandbox(dir string, binding sandboxBinding, create bool) error {
	path := filepath.Join(dir, sandboxBindingName)
	var saved sandboxBinding
	err := readStorageJSON(path, &saved)
	switch {
	case err == nil && saved != binding:
		return fmt.Errorf("the keys in %s belong to a sandbox of Monitor %s in another account or Monitor", dir, saved.Monitor)
	case err == nil || !errors.Is(err, os.ErrNotExist) || !create:
		return err
	}
	return writeStorageJSON(path, binding, true)
}

// Bind keys, register identities and restrict networking before creation.
func prepareSandboxMonitor(client *cpClient, row containerView, name, monitor string, credential *ownerCredential, variables map[string]string) (containerNetworkPolicy, error) {
	policy := containerNetworkPolicy{EgressMode: "restricted"}
	scope, _, err := currentScope()
	if err != nil {
		return policy, err
	}
	peer, err := containerNamed(client, monitor)
	if err != nil {
		return policy, err
	}
	if _, err := workloadSource(peer, monitorRepo); err != nil {
		return policy, err
	}
	policy.Egress = []containerPeer{{peer.ID, 22}}
	binding := sandboxBinding{scope, monitor}
	if row.ID != "" {
		p := row.NetworkPolicy
		if p == nil || p.EgressMode == "unrestricted" || p.Public || len(p.Egress) != 1 || p.Egress[0] != policy.Egress[0] {
			return policy, fmt.Errorf("sandbox %s already exists and is not contained by Monitor %s", name, monitor)
		}
	}
	keys, err := sandboxKeysFor(name, binding, row.ID == "", credential)
	if err != nil {
		return policy, err
	}
	defer clear(keys.ownerSeed)
	if row.ID == "" {
		owner, dir, err := connectMonitorOwner(context.Background(), scope, peer, false)
		if err != nil {
			return policy, err
		}
		defer owner.Close()
		if err := sandboxBootMonitor(scope, peer, variables); err != nil {
			return policy, err
		}
		device, err := loadSSHKey(filepath.Join(dir, monitorDeviceKeyName))
		if err != nil {
			return policy, err
		}
		if err := pairSandboxMonitor(owner, dir, name, device, keys.agentKey); err != nil {
			return policy, err
		}
	}
	fmt.Fprintf(os.Stderr, "Grant account access to sandbox %s in the Monitor UI.\n", name)
	return policy, nil
}

// Only public Monitor details enter the launch configuration.
func sandboxBootMonitor(scope accountScope, peer containerView, variables map[string]string) error {
	_, key, err := verifyMonitor(scope, peer, false)
	if err != nil {
		return err
	}
	address, err := monitorAddress(context.Background(), peer)
	if err != nil {
		return err
	}
	route := map[string]any{}
	if raw := variables["MONITOR_ROUTE"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &route); err != nil || route == nil {
			return errors.New("MONITOR_ROUTE must be a JSON object")
		}
	}
	// An explicit sandbox-facing address can differ from the device's public one.
	if supplied, ok := route["address"].(string); ok && supplied != "" {
		address = supplied
	}
	ip, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || !validMonitorEndpoint(ip, port) {
		return errors.New("MONITOR_ROUTE address must be an IPv4 address and SSH port")
	}
	// Never copy credentials or a caller-supplied host key into boot configuration.
	public := map[string]any{"domain": peer.Domain, "ip": ip, "port": port,
		"host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}
	if route["address"] != nil {
		public["address"] = address
	}
	data, err := json.Marshal(public)
	if err == nil {
		variables["MONITOR_ROUTE"] = string(data)
	}
	return err
}

// One command keeps one verified sandbox connection through enrollment and SSH setup.
type sandboxSession struct {
	box     sandboxView
	keys    *sandboxKeys
	expires time.Time
	monitor *ssh.Client
	profile sshProfile
}

func connectSandbox(box sandboxView) (_ *sandboxSession, err error) {
	if box.State != sandboxStateRunning {
		return nil, fmt.Errorf("sandbox %s is %s; start it before enrolling", box.ID, box.State)
	}
	if box.Domain == "" {
		return nil, fmt.Errorf("sandbox %s reported no domain", box.ID)
	}
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	keys, err := loadSandboxKeys(box.ID)
	if err != nil {
		return nil, err
	}
	var row containerView
	_, err = client.do("GET", pathf("/api/containers/%s", box.ContainerID), nil, nil, &row)
	if err != nil {
		return nil, err
	}
	if row.Domain != box.Domain {
		return nil, errors.New("sandbox domain changed while connecting")
	}
	source, err := workloadSource(row, defaultSandboxRepo)
	if err != nil {
		return nil, err
	}
	s := &sandboxSession{box: box, keys: keys}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if err := s.configureMonitor(client, row); err != nil {
		return nil, err
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		for {
			conn, err := s.monitor.DialContext(ctx, "tcp", net.JoinHostPort(bootstrapRoute((&ownerCredential{SigningSeed: keys.ownerSeed}).publicKey()), "443"))
			var channel *ssh.OpenChannelError
			if !errors.As(err, &channel) || channel.Reason != ssh.ConnectionFailed {
				return conn, err
			}
			// Readiness can precede the first reverse connection or its systemd handoff.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	host, expires, err := attestConnection(dial, box.Domain, source)
	if err != nil {
		return nil, err
	}
	s.expires = expires
	s.profile = sshProfile{name: box.ID, hostName: routeName(host), port: defaultSSHPort, hostKeyAlias: box.Domain,
		user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: host, jump: s.profile.jump}
	return s, nil
}

func (s *sandboxSession) close() {
	if s.monitor != nil {
		s.monitor.Close()
	}
	clear(s.keys.ownerSeed)
}

func (s *sandboxSession) configureMonitor(client *cpClient, row containerView) error {
	peer, endpoint, err := sandboxPeer(client, row)
	if err != nil {
		return err
	}
	scope, _, err := currentScope()
	if err != nil {
		return err
	}
	if err := bindSandbox(s.keys.dir, sandboxBinding{scope, peer.Name}, false); err != nil {
		return err
	}
	_, hostKey, err := verifyMonitor(scope, peer, false)
	if err != nil {
		return err
	}
	variables, err := measuredEnvironment(row.Config)
	if err != nil {
		return err
	}
	var route map[string]any
	if err := json.Unmarshal([]byte(variables["MONITOR_ROUTE"]), &route); err != nil {
		return errors.New("sandbox has no Monitor boot configuration; restart it")
	}
	key, _ := route["host_key"].(string)
	if route["domain"] != peer.Domain || !sameSSHKey(key, string(ssh.MarshalAuthorizedKey(hostKey))) {
		return errors.New("sandbox Monitor boot pin changed; restart it after explicitly repinning Monitor")
	}
	if route["ip"] != endpoint.IP || route["port"] != float64(endpoint.Port) {
		return fmt.Errorf("sandbox boot address does not match its allowed Monitor endpoint %s; supply that address in MONITOR_ROUTE at launch", net.JoinHostPort(endpoint.IP, strconv.Itoa(endpoint.Port)))
	}
	dir, err := monitorDir(scope, peer.Name)
	if err != nil {
		return err
	}
	devicePath := filepath.Join(dir, monitorDeviceKeyName)
	device, err := os.ReadFile(devicePath)
	if err != nil {
		return err
	}
	defer clear(device)
	signer, err := ssh.ParsePrivateKey(device)
	if err != nil {
		return err
	}
	address, err := monitorAddress(context.Background(), peer)
	if err != nil {
		return err
	}
	s.monitor, err = ssh.Dial("tcp", address, &ssh.ClientConfig{
		User: monitorSSHUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	identity, err := os.ReadFile(filepath.Join(s.keys.dir, sandboxAgentKeyName))
	if err != nil {
		return err
	}
	s.keys.monitorIdentity = string(identity)
	ip, port, _ := net.SplitHostPort(address)
	portNumber, _ := strconv.Atoi(port)
	s.profile.jump = &sshProfile{name: s.box.ID + monitorJumpSuffix, hostName: ip, port: portNumber,
		user: monitorSSHUser, identityFile: devicePath, hostKey: hostKey, hostKeyAlias: peer.Domain}
	return nil
}

func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

func (s *sandboxSession) enrolled() bool {
	key, _ := os.ReadFile(filepath.Join(s.keys.dir, sandboxEnrolledKeyName))
	return sameSSHKey(string(key), string(ssh.MarshalAuthorizedKey(s.profile.hostKey)))
}

func (s *sandboxSession) enroll() error {
	if s.enrolled() {
		return nil
	}
	dial := func() (*ssh.Client, error) {
		if !time.Now().Before(s.expires) {
			return nil, errors.New("sandbox attestation expired; verify it again before unlocking")
		}
		ctx, cancel := context.WithTimeout(context.Background(), sandboxEnrollTimeout)
		defer cancel()
		conn, err := s.monitor.DialContext(ctx, "tcp", net.JoinHostPort(s.profile.hostName, "22"))
		if err != nil {
			return nil, err
		}
		client, err := connectOwnerSSHAs(conn, s.box.Domain, s.profile.hostKey, s.keys.ownerSeed, sandboxLoginUser)
		if err == nil && !time.Now().Before(s.expires) {
			client.Close()
			return nil, errors.New("sandbox attestation expired during SSH handshake")
		}
		return client, err
	}
	if err := sendUnlock(dial, s.keys); err != nil {
		return fmt.Errorf("%w; retry with `tinfoil sandbox enroll %s`", err, s.box.ID)
	}
	if err := writeAtomic(filepath.Join(s.keys.dir, sandboxEnrolledKeyName), ssh.MarshalAuthorizedKey(s.profile.hostKey)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Unlocked %s over SSH with the keys in %s\n", s.box.ID, s.keys.dir)
	return nil
}

func (s *sandboxSession) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return installSandboxAlias(s.profile, home)
}

// Verify fresh evidence and the boot TLS key before authorizing SSH unlock.
func attestConnection(dial func(context.Context, string, string) (net.Conn, error), host, source string) (ssh.PublicKey, time.Time, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, time.Time{}, err
	}
	// This bootstrap request sends only a public freshness nonce. The document
	// is authenticated by VerifyV3 below, then its attested TLS key is matched
	// against this exact response before its SSH key is trusted.
	fetch := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}, Timeout: sandboxEnrollTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer fetch.CloseIdleConnections()
	resp, err := fetch.Get("https://" + host + sandboxAttestationPath + "?nonce=" + hex.EncodeToString(nonce))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fetching the attestation of %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("fetching the attestation of %s: %s", host, resp.Status)
	}
	doc, err := io.ReadAll(io.LimitReader(resp.Body, maxSandboxAttestationBytes+1))
	if err == nil && len(doc) > maxSandboxAttestationBytes {
		err = fmt.Errorf("it exceeds %d bytes", maxSandboxAttestationBytes)
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reading the attestation of %s: %w", host, err)
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, time.Time{}, err
	}
	verified, err := verifier.VerifyV3(doc, nonce, source)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("verifying %s: %w", host, err)
	}
	key, err := endorsedHostKey(host, verified)
	if err != nil {
		return nil, time.Time{}, err
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, time.Time{}, errors.New("sandbox boot key has no TLS representation")
	}
	fingerprint, err := enclave.CertPubkeyFP(&x509.Certificate{PublicKey: cryptoKey.CryptoPublicKey()})
	if err != nil {
		return nil, time.Time{}, err
	}
	if resp.TLS == nil {
		return nil, time.Time{}, errors.New("sandbox supplied no TLS key")
	}
	if err := pinnedTLS(fingerprint)(*resp.TLS); err != nil {
		return nil, time.Time{}, fmt.Errorf("sandbox TLS: %w", err)
	}
	return key, verified.FreshnessExpiresAt, nil
}

// Preserve aliases owned by another identity.
func installSandboxAlias(p sshProfile, home string) error {
	if owned, err := ownsSSHProfile(home, p.name, p.identityFile); err != nil || !owned {
		return errors.Join(err, fmt.Errorf("~/.ssh/tinfoil/%s.conf is the profile of another host; remove it so `ssh %s` reaches this sandbox", p.name, p.name))
	}
	return p.installTo(home, os.Stdin, os.Stderr, false, true)
}

func ownsSSHProfile(home, name, identityFile string) (bool, error) {
	existing, err := os.ReadFile(filepath.Join(home, ".ssh", "tinfoil", name+".conf"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	owned := bytes.Contains(existing, []byte("\n  IdentityFile "+identityFile+"\n"))
	// Upgrade this sandbox's old profile without overwriting its old private key.
	if filepath.Base(identityFile) == sandboxSSHKeyName {
		legacy := filepath.Join(filepath.Dir(identityFile), "id_ed25519")
		owned = owned || bytes.Contains(existing, []byte("\n  IdentityFile "+legacy+"\n"))
	}
	return owned, err
}

// Remove the local SSH profile while keeping the saved keys.
func forgetSandbox(name string) error {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return err
	}
	var binding sandboxBinding
	if err := readStorageJSON(filepath.Join(dir, sandboxBindingName), &binding); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	scope, _, err := currentScope()
	if err != nil {
		return err
	}
	if binding.Scope != scope {
		return errors.New("saved sandbox belongs to another account")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	owned, err := ownsSSHProfile(home, name, filepath.Join(dir, sandboxSSHKeyName))
	if err != nil {
		return err
	}
	if owned {
		for _, file := range []string{name + ".conf", name + ".known_hosts"} {
			if err := os.Remove(filepath.Join(home, ".ssh", "tinfoil", file)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func loadSSHKey(path string) (string, error) {
	signer, err := loadSigner(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

func sameSSHKey(a, b string) bool {
	x, _, _, _, errX := ssh.ParseAuthorizedKey([]byte(a))
	y, _, _, _, errY := ssh.ParseAuthorizedKey([]byte(b))
	return errX == nil && errY == nil && bytes.Equal(x.Marshal(), y.Marshal())
}

// Repeat only after transport failures. The server accepts identical retries of
// this boot's unlock, including after its SSH daemon hands off to normal login.
func sendUnlock(dial func() (*ssh.Client, error), keys *sandboxKeys) error {
	body, err := json.Marshal(struct {
		Volume          string `json:"volume"`
		MonitorIdentity string `json:"monitor_identity"`
	}{keys.diskKey, keys.monitorIdentity})
	if err != nil {
		return err
	}
	defer clear(body)
	deadline := time.Now().Add(sandboxBootTimeout)
	for attempt := 0; attempt < 3; attempt++ {
		client, dialErr := dial()
		err = dialErr
		if err == nil {
			timer := time.AfterFunc(time.Until(deadline), func() { client.Close() })
			var session *ssh.Session
			session, err = client.NewSession()
			if err == nil {
				session.Stdin = bytes.NewReader(body)
				var message limitedUnlockOutput
				session.Stderr = &message
				err = session.Run("/usr/local/libexec/workspace-enroll --unlock")
				session.Close()
				var refused *ssh.ExitError
				if errors.As(err, &refused) {
					timer.Stop()
					client.Close()
					return fmt.Errorf("workspace unlock refused: %s", strings.TrimSpace(string(message)))
				}
			}
			timer.Stop()
			client.Close()
		}
		if err == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("workspace unlock timed out: %w", err)
		}
		if attempt < 2 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return fmt.Errorf("workspace SSH unlock: %w", err)
}

type limitedUnlockOutput []byte

func (b *limitedUnlockOutput) Write(p []byte) (int, error) {
	n := min(len(p), maxEnrollReplyBytes-len(*b))
	*b = append(*b, p[:n]...)
	return len(p), nil
}
