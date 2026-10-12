package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
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

// Resolve the allowed endpoint only for explicit lifecycle preparation.
func sandboxPeer(client *cpClient, row containerView) (sandboxEndpoint, error) {
	var network struct {
		Egress []sandboxEndpoint `json:"egress"`
	}
	policy := row.NetworkPolicy
	if policy == nil || policy.EgressMode == "unrestricted" || policy.Public || len(policy.Egress) != 1 || policy.Egress[0].Port != 22 {
		return sandboxEndpoint{}, errors.New("sandbox network policy does not name one SSH peer")
	}
	if _, err := client.do("GET", pathf("/api/containers/%s/network", row.ID), nil, nil, &network); err != nil {
		return sandboxEndpoint{}, err
	}
	if len(network.Egress) != 1 || !validMonitorEndpoint(network.Egress[0].IP, network.Egress[0].Port) {
		return sandboxEndpoint{}, errors.New("peer is unavailable")
	}
	return network.Egress[0], nil
}

func validMonitorEndpoint(ip string, port int) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil && port >= 1 && port <= maxConnectionPort
}

// One command keeps one verified sandbox connection through enrollment and SSH setup.
type sandboxSession struct {
	box         sandboxView
	keys        *sandboxKeys
	expires     time.Time
	monitor     *ssh.Client
	profile     sshProfile
	signer      ssh.Signer
	signerClose func()
	binding     monitorBinding
	claim       string
	monitorKey  string
	initialized bool
}

type sandboxReceipt struct {
	BootKey    string `json:"boot_key"`
	MonitorKey string `json:"monitor_key"`
}

func connectSandbox(box sandboxView) (*sandboxSession, error) {
	cp, err := authedClient()
	if err != nil {
		return nil, err
	}
	var row containerView
	if _, err := cp.do("GET", pathf("/api/containers/%s", box.ContainerID), nil, nil, &row); err != nil {
		return nil, err
	}
	return connectSandboxRow(row)
}

func connectSandboxRow(row containerView) (_ *sandboxSession, err error) {
	if row.Volumes == nil {
		cp, err := authedClient()
		if err != nil {
			return nil, err
		}
		id := row.ID
		if _, err := cp.do("GET", pathf("/api/containers/%s", id), nil, nil, &row); err != nil {
			return nil, err
		}
		if row.ID != id {
			return nil, errors.New("sandbox resource changed while resolving it")
		}
	}
	if len(row.Volumes) != 1 || !looksLikeUUID(row.Volumes["workspace"]) {
		return nil, errors.New("sandbox has no unique workspace volume binding")
	}
	if row.Status != statusRunning {
		return nil, fmt.Errorf("sandbox %s is %s; start it before connecting", row.Name, row.Status)
	}
	source, err := workloadSource(row, defaultSandboxRepo)
	if err != nil {
		return nil, err
	}
	env, err := measuredEnvironment(row.Config, true)
	if err != nil {
		return nil, err
	}
	var binding monitorBinding
	if json.Unmarshal([]byte(env["MONITOR_BINDING"]), &binding) != nil || !looksLikeUUID(env["SANDBOX_INSTANCE_ID"]) || !looksLikeUUID(binding.ContainerID) {
		return nil, errors.New("sandbox release lacks measured instance and Monitor bindings; use compatible templates")
	}
	scope, cp, err := currentScope()
	if err != nil {
		return nil, err
	}
	dir, err := sandboxKeyDir(row.Name)
	if err != nil {
		return nil, err
	}
	var legacy sandboxBinding
	if readStorageJSON(filepath.Join(dir, sandboxBindingName), &legacy) != nil || legacy.Scope != scope {
		dir, err = resourceDir(scope, row.ID)
		if err != nil {
			return nil, err
		}
	}
	record := struct {
		ID, Instance, Owner string
		Monitor             monitorBinding
		Volumes             map[string]string
	}{row.ID, env["SANDBOX_INSTANCE_ID"], env[sandboxOwnerEnv], binding, row.Volumes}
	raw, _ := json.Marshal(record)
	saved, readErr := os.ReadFile(filepath.Join(dir, "resource.json"))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if readErr == nil && !bytes.Equal(saved, raw) {
		return nil, errors.New("sandbox owner, storage or Monitor binding changed")
	}
	credential, err := resourceCredential(dir, sandboxDiskKeyName, env[sandboxOwnerEnv], readErr == nil)
	if err != nil {
		return nil, err
	}
	defer credential.clear()
	keys := &sandboxKeys{dir: dir, diskKey: base64.StdEncoding.EncodeToString(credential.Key)}
	if readErr != nil {
		if _, err := ensureSSHKey(filepath.Join(dir, sandboxAgentKeyName)); err != nil {
			return nil, err
		}
	}
	keys.agentKey, err = loadSSHKey(filepath.Join(dir, sandboxAgentKeyName))
	if err != nil {
		return nil, err
	}
	identity, err := os.ReadFile(filepath.Join(dir, sandboxAgentKeyName))
	if err != nil {
		return nil, err
	}
	keys.monitorIdentity = string(identity)
	if err := writeAtomic(filepath.Join(dir, "resource.json"), raw); err != nil {
		return nil, err
	}
	s := &sandboxSession{box: sandboxFromContainer(row), keys: keys, binding: binding, claim: "sandbox-v2:" + record.Instance}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.signer, keys.sshKeyPath, s.signerClose, err = ownerSigner(credential, dir)
	if err != nil {
		return nil, err
	}
	if len(credential.SigningSeed) != 0 {
		if err := ensureOwnerSSHKey(keys.sshKeyPath, credential.SigningSeed); err != nil {
			return nil, err
		}
	}
	var receipt sandboxReceipt
	if err := readStorageJSON(filepath.Join(dir, sandboxEnrolledKeyName), &receipt); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.initialized = receipt.BootKey != ""
	if err := s.configureMonitor(cp, scope, row); err != nil {
		return nil, err
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		for {
			conn, err := s.monitor.DialContext(ctx, "tcp", net.JoinHostPort(bootstrapRoute(s.claim), "443"))
			var channel *ssh.OpenChannelError
			if !errors.As(err, &channel) || channel.Reason != ssh.ConnectionFailed {
				return conn, err
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	host, expires, err := attestConnection(dial, row.Domain, source)
	if err != nil {
		var denied *ssh.OpenChannelError
		if errors.As(err, &denied) && denied.Reason == ssh.Prohibited {
			return nil, errors.New("Monitor route access denied; restore this device explicitly in the Monitor UI")
		}
		return nil, fmt.Errorf("%w; if the Monitor endpoint or host grant changed, restart this sandbox explicitly", err)
	}
	s.expires = expires
	s.profile = sshProfile{name: row.Name, hostName: routeName(host), port: defaultSSHPort, hostKeyAlias: row.Domain,
		user: sandboxLoginUser, identityFile: keys.sshKeyPath, hostKey: host, jump: s.profile.jump, resourceID: scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + row.ID}
	return s, nil
}

func (s *sandboxSession) close() {
	if s.monitor != nil {
		s.monitor.Close()
	}
	if s.signerClose != nil {
		s.signerClose()
	}
}

func (s *sandboxSession) configureMonitor(cp *cpClient, scope accountScope, row containerView) error {
	policy := row.NetworkPolicy
	if policy == nil || policy.Public || policy.EgressMode != "restricted" || len(policy.Egress) != 1 || policy.Egress[0] != (containerPeer{s.binding.ContainerID, 22}) {
		return errors.New("sandbox network policy does not match its measured Monitor binding")
	}
	dir, err := resourceDir(scope, s.binding.ContainerID)
	if err != nil {
		return err
	}
	var profile monitorProfile
	err = readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	connect := func() error {
		if profile.Owner != s.binding.Owner {
			return errors.New("Monitor owner changed")
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(profile.HostKey))
		if err != nil {
			return err
		}
		device, err := loadSigner(filepath.Join(dir, monitorDeviceKeyName))
		if err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", profile.Address, 30*time.Second)
		if err != nil {
			return err
		}
		s.monitor, err = connectOwnerSigner(conn, profile.Domain, key, device, monitorSSHUser)
		return err
	}
	if err := connect(); err != nil || !s.initialized {
		if s.monitor != nil {
			s.monitor.Close()
		}
		var peer containerView
		if _, err := cp.do("GET", pathf("/api/containers/%s", s.binding.ContainerID), nil, nil, &peer); err != nil {
			return err
		}
		env, err := measuredEnvironment(peer.Config, false)
		if err != nil {
			return err
		}
		if peer.Status != statusRunning {
			return fmt.Errorf("Monitor %s is %s; start it before connecting", peer.Name, peer.Status)
		}
		if env[monitorOwnerEnv] != s.binding.Owner {
			return errors.New("Monitor does not match the sandbox's measured owner binding")
		}
		owner, ownerDir, err := connectMonitorOwner(context.Background(), scope, peer)
		if err != nil {
			return err
		}
		defer owner.Close()
		dir = ownerDir
		device, err := loadSSHKey(filepath.Join(dir, monitorDeviceKeyName))
		if err != nil {
			return fmt.Errorf("restore Monitor device key: %w", err)
		}
		if err := pairSandboxMonitor(owner, dir, s.box.ID, device, s.keys.agentKey); err != nil {
			return err
		}
		if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
			return err
		}
		if err := connect(); err != nil {
			return err
		}
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(profile.HostKey))
	if err != nil {
		return err
	}
	ip, port, _ := net.SplitHostPort(profile.Address)
	portNumber, _ := strconv.Atoi(port)
	s.monitorKey = profile.HostKey
	s.profile.jump = &sshProfile{name: s.box.ID + monitorJumpSuffix, hostName: ip, port: portNumber, user: monitorSSHUser, identityFile: filepath.Join(dir, monitorDeviceKeyName), hostKey: key, hostKeyAlias: profile.Domain}
	return nil
}

func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

func (s *sandboxSession) enrolled() bool {
	var receipt sandboxReceipt
	return readStorageJSON(filepath.Join(s.keys.dir, sandboxEnrolledKeyName), &receipt) == nil &&
		sameSSHKey(receipt.BootKey, string(ssh.MarshalAuthorizedKey(s.profile.hostKey))) && sameSSHKey(receipt.MonitorKey, s.monitorKey)
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
		client, err := connectOwnerSigner(conn, s.box.Domain, s.profile.hostKey, s.signer, sandboxLoginUser)
		if err == nil && !time.Now().Before(s.expires) {
			client.Close()
			return nil, errors.New("sandbox attestation expired during SSH handshake")
		}
		return client, err
	}
	var receipt sandboxReceipt
	_ = readStorageJSON(filepath.Join(s.keys.dir, sandboxEnrolledKeyName), &receipt)
	operation := "initialize"
	if s.initialized {
		operation = "unlock"
	}
	if sameSSHKey(receipt.BootKey, string(ssh.MarshalAuthorizedKey(s.profile.hostKey))) {
		operation = "route"
	}
	request := map[string]any{"operation": operation, "monitor_route": map[string]any{"binding": s.binding, "host_key": s.monitorKey}}
	if operation != "route" {
		request["volume"], request["monitor_identity"] = s.keys.diskKey, s.keys.monitorIdentity
	}
	if err := sendOwnerRequest(dial, request); err != nil {
		return fmt.Errorf("%w; retry with `tinfoil sandbox enroll %s`", err, s.box.ID)
	}
	if err := writeStorageJSON(filepath.Join(s.keys.dir, sandboxEnrolledKeyName), sandboxReceipt{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.profile.hostKey))), s.monitorKey}, false); err != nil {
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
	if owned, err := ownsSSHProfile(home, p.name, p.resourceID); err != nil || !owned {
		return errors.Join(err, fmt.Errorf("~/.ssh/tinfoil/%s.conf is the profile of another resource; choose --name ALIAS or remove this profile", p.name))
	}
	return p.installTo(home, os.Stdin, os.Stderr, false, true)
}

func ownsSSHProfile(home, name, resource string) (bool, error) {
	existing, err := os.ReadFile(filepath.Join(home, ".ssh", "tinfoil", name+".conf"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return resource != "" && bytes.HasPrefix(existing, []byte("# tinfoil-resource: "+resource+"\n")), err
}

// Remove the local SSH profile while keeping the saved keys.
func forgetSandbox(name, id string) error {
	if id == "" {
		return nil
	}
	scope, _, err := currentScope()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	owned, err := ownsSSHProfile(home, name, scope.ControlplaneURL+"/"+scope.OrgID+"/"+scope.UserID+"/"+id)
	if err != nil || !owned {
		return err
	}
	for _, suffix := range []string{".conf", ".known_hosts"} {
		if err := os.Remove(filepath.Join(home, ".ssh", "tinfoil", name+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
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
func sendOwnerRequest(dial func() (*ssh.Client, error), request any) error {
	body, err := json.Marshal(request)
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
				err = session.Run("/usr/local/bin/workspace-unlock")
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
