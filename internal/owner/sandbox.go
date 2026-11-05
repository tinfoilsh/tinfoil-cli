package owner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSandboxRepo = "tinfoilsh/confidential-agent-sandbox"
	sandboxOwnerEnv    = "SANDBOX_OWNER_PUBLIC_KEY"
	// sandboxWorkspaceSlot is the volume mount that holds a sandbox's workspace.
	sandboxWorkspaceSlot = "workspace"
)

// The fixed endpoint is usable only with an explicit matching alias policy.
func SandboxNetworkMatches(row controlplane.Container) bool {
	policy := row.NetworkPolicy
	if policy == nil || policy.Public || policy.EgressMode != "restricted" || len(policy.Egress) != 1 {
		return false
	}
	peer := policy.Egress[0]
	return resourceIDPattern.MatchString(peer.ContainerID) && peer.Port == 22 && peer.Alias != nil &&
		*peer.Alias == (controlplane.Alias{IP: "10.254.0.1", Port: 22})
}

func ValidateSandboxNetwork(row controlplane.Container, env map[string]string) error {
	if env["NO_MONITOR"] == "1" {
		if row.NetworkPolicy != nil {
			return errors.New("sandbox with NO_MONITOR=1 must have no network policy")
		}
		return nil
	}
	if !SandboxNetworkMatches(row) {
		return errors.New("sandbox requires a private TCP alias for its selected Monitor; update its network policy")
	}
	return nil
}

const (
	sandboxOwnerProtocol = "sandbox-owner-v1"
	sandboxOwnerRequest  = "sudo -n -- curl -sS --fail-with-body --unix-socket /run/workspace/owner.sock http://sandbox"
	sandboxStatusCommand = sandboxOwnerRequest + "/status"
	sandboxEnrollCommand = sandboxOwnerRequest + "/enroll --data-binary @-"

	// Monitor routes to a sandbox boot by a name derived from its SSH host key.
	sandboxRouteSuffix = ".sandbox.invalid"
)

// One command keeps one verified sandbox connection through enrollment and SSH setup.
type Sandbox struct {
	service   *Service
	box       controlplane.Container
	keys      *resourceKeys
	binding   mkBinding
	expires   time.Time
	monitor   *Monitor
	owner     *sandboxOwner
	profile   ConnectionInfo
	noMonitor bool
}

func (s *Service) OpenSandbox(ctx context.Context, scope Scope, cp *controlplane.Client, target *Workload, monitor *Monitor, verifier Verifier) (_ *Sandbox, err error) {
	row := target.Container
	binding, err := SandboxBinding(scope, target)
	if err != nil {
		return nil, err
	}
	dir, err := ResourceDir(s.ConfigPath, scope, row.ID, row.Name)
	if err != nil {
		return nil, err
	}
	keys, err := s.resolveResourceKeys(ctx, cp, scope, row, "sandbox", binding, dir, true)
	if err != nil {
		return nil, err
	}
	return s.openSandbox(scope, target, binding, monitor, keys, dir, verifier)
}

func SandboxBinding(scope Scope, target *Workload) (mkBinding, error) {
	row, env := target.Container, target.Environment
	if err := requireRunningConnection("Sandbox", row); err != nil {
		return mkBinding{}, err
	}
	volumeID, instance := row.Volumes[sandboxWorkspaceSlot], env["SANDBOX_INSTANCE_ID"]
	if len(row.Volumes) != 1 || !validLowerUUID(volumeID) {
		return mkBinding{}, errors.New("sandbox has no unique workspace volume binding")
	}
	if !validLowerUUID(instance) {
		return mkBinding{}, errors.New("sandbox release lacks a measured instance ID; use compatible templates")
	}
	if env[sandboxOwnerEnv] != row.OwnerPublicKey {
		return mkBinding{}, errors.New("sandbox's measured owner is not its owner key")
	}
	if err := ValidateSandboxNetwork(row, env); err != nil {
		return mkBinding{}, err
	}
	if env["NO_MONITOR"] == "1" && (row.SSHPort < 1 || row.SSHPort > maxConnectionPort) {
		return mkBinding{}, errors.New("sandbox has no published SSH port")
	}
	return mkBinding{Account: scope.Account(), ContainerID: row.ID, InstanceID: &instance, VolumeID: &volumeID}, nil
}

func (service *Service) openSandbox(scope Scope, target *Workload, binding mkBinding, monitor *Monitor, keys *resourceKeys, dir string, verifier Verifier) (_ *Sandbox, err error) {
	row := target.Container
	noMonitor := monitor == nil
	s := &Sandbox{service: service, box: row, noMonitor: noMonitor, binding: binding, keys: keys, monitor: monitor}
	defer func() {
		if err != nil {
			keys.close()
		}
	}()
	identity := keys.identity
	if keys.mode == "tmk" {
		if identity, err = service.exportTMKIdentity(dir, keys.ownerSeed); err != nil {
			return nil, err
		}
	}
	resourceID := scope.ControlplaneURL + "/" + scope.OrgID + "/" + scope.UserID + "/" + row.ID
	if noMonitor {
		defer service.progress(SandboxVerifying, row.Domain)()
		verified, err := verifier.DirectHost(context.Background(), row.Domain, target.Source)
		if err != nil {
			return nil, err
		}
		s.expires = verified.Expires
		s.profile = ConnectionInfo{Name: row.Name, HostName: row.Domain, Port: row.SSHPort, HostKeyAlias: row.Domain,
			User: sandboxLoginUser, IdentityFile: identity, HostKey: verified.Key, ResourceID: resourceID}
		service.notify(SandboxDirectVerified, row.Name)
		return s, nil
	}
	s.owner = &sandboxOwner{request: monitor.request, instance: *binding.InstanceID, dial: s.dial}
	stop := service.progress(SandboxRelayVerifying, row.Name)
	verified, err := s.owner.attest(row.Domain, target.Source, verifier)
	stop()
	if err != nil {
		return nil, fmt.Errorf("sandbox attestation through Monitor: %w", err)
	}
	host := verified.Key
	s.expires = verified.Expires
	service.notify(SandboxVerified, row.Name)
	address, port, _ := net.SplitHostPort(monitor.address)
	portNumber, _ := strconv.Atoi(port)
	s.profile = ConnectionInfo{Name: row.Name, HostName: routeName(host), Port: defaultSSHPort, HostKeyAlias: row.Domain,
		User: sandboxLoginUser, IdentityFile: identity, HostKey: host, ResourceID: resourceID,
		Jump: monitorJump(row.Name, address, portNumber, monitor.dir, monitor.hostKey, monitor.domain)}
	return s, nil
}

func (service *Service) RelinkSandbox(ctx context.Context, scope Scope, cp *controlplane.Client, m *Monitor, monitorID, id string, target *Workload, verifier Verifier) (*ConnectionInfo, error) {
	row := &target.Container
	if row.ID != id || row.ClerkUserID != scope.UserID || row.Status != "running" || !SandboxNetworkMatches(*row) || row.NetworkPolicy.Egress[0].ContainerID != monitorID {
		return nil, errors.New("its inventory changed while re-linking")
	}
	if m.keys.mode == "umk" && row.OwnerKeyMode == "tmk" {
		return nil, fmt.Errorf("a UMK Monitor cannot serve the synced sandbox %s", row.Name)
	}
	binding, err := SandboxBinding(scope, target)
	if err != nil {
		return nil, err
	}
	dir, err := ResourceDir(service.ConfigPath, scope, row.ID, row.Name)
	if err != nil {
		return nil, err
	}
	keys, err := service.resolveResourceKeys(ctx, cp, scope, *row, "sandbox", binding, dir, false)
	if err != nil {
		return nil, err
	}
	if !m.authorizes(monitorIdentity(keys.monitorIdentitySeed)) {
		keys.close()
		return nil, nil
	}
	s, err := service.openSandbox(scope, target, binding, m, keys, dir, verifier)
	if err != nil {
		return nil, err
	}
	defer keys.close()
	status, err := s.status(ctx)
	if err != nil {
		return nil, err
	}
	if status.MonitorIdentity == nil || *status.MonitorIdentity != monitorIdentity(keys.monitorIdentitySeed) {
		return nil, fmt.Errorf("its saved Monitor identity is not active; run `tinfoil sandbox start %s`", row.Name)
	}
	if host := authorizedKeyLine(m.hostKey); status.MonitorHostKey == nil || *status.MonitorHostKey != host {
		service.notify(SandboxRelinking, row.Name)
		if err := s.enrollSandbox(ctx, status.Volume, host); err != nil {
			return nil, err
		}
	}
	return &s.profile, nil
}

func (s *Sandbox) close() {
	if s.keys != nil {
		s.keys.close()
	}
	if s.monitor != nil {
		s.monitor.close()
	}
}

// monitorJump is the hop through the Monitor. It must present the device key:
// the Monitor gives its owner key (by default the user's ~/.ssh/id_ed25519)
// an owner-only session that cannot open routes to sandboxes, and that key is
// usually in ssh-agent. The device key is an unencrypted file, so the hop needs
// no agent.
func monitorJump(sandbox, host string, port int, dir string, hostKey ssh.PublicKey, domain string) *ConnectionInfo {
	return &ConnectionInfo{Name: sandbox + monitorJumpSuffix, HostName: host, Port: port, User: monitorSSHUser, IdentityFile: filepath.Join(dir, monitorDeviceKeyName), HostKey: hostKey, HostKeyAlias: domain, NoAgent: true}
}

type sandboxStatus struct {
	Protocol        string  `json:"protocol"`
	InstanceID      string  `json:"instance_id"`
	Volume          string  `json:"volume"`
	MonitorIdentity *string `json:"monitor_identity"`
	MonitorHostKey  *string `json:"monitor_host_key"`
}

func (s *Sandbox) Enroll(ctx context.Context) error {
	if !time.Now().Before(s.expires) {
		return errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	if s.noMonitor {
		return s.unlockDirect(ctx)
	}
	name := s.box.Name
	status, err := s.status(ctx)
	if err != nil {
		return err
	}
	agent := ""
	if s.keys.monitorIdentitySeed != nil {
		agent = monitorIdentity(s.keys.monitorIdentitySeed)
	}
	host := authorizedKeyLine(s.monitor.hostKey)
	switch {
	case status.MonitorIdentity != nil && *status.MonitorIdentity != agent:
		return fmt.Errorf("sandbox %s holds a different Monitor identity than its saved keys", name)
	case status.MonitorIdentity == nil && (agent == "" || !s.monitor.authorizes(agent)):
		if s.keys.storageKey == nil {
			if err := s.keys.generateUMKKeys("sandbox", s.box.OwnerPublicKey, s.binding); err != nil {
				return err
			}
			agent = monitorIdentity(s.keys.monitorIdentitySeed)
		}
		s.service.notify(SandboxRegistering, name)
		if err := s.monitor.enrollAgent(ctx, "sandbox-"+name, agent); err != nil {
			return err
		}
		return s.enrollSandbox(ctx, status.Volume, host)
	case !s.monitor.authorizes(agent):
		return fmt.Errorf("Monitor no longer authorizes sandbox %s; restore its identity in the Monitor UI, then retry", name)
	case status.MonitorIdentity == nil || status.Volume != "unlocked":
		return s.enrollSandbox(ctx, status.Volume, host)
	case status.MonitorHostKey == nil || *status.MonitorHostKey != host:
		s.service.notify(SandboxRelinking, name)
		return s.enrollSandbox(ctx, status.Volume, host)
	}
	return nil
}

func (s *Sandbox) status(ctx context.Context) (sandboxStatus, error) {
	var status sandboxStatus
	if err := s.owner.call(ctx, sandboxStatusCommand, nil, &status); err != nil {
		return status, err
	}
	if status.Protocol != sandboxOwnerProtocol || status.InstanceID != s.owner.instance {
		return status, errors.New("sandbox owner status names another protocol or instance")
	}
	return status, nil
}

func (s *Sandbox) enrollSandbox(ctx context.Context, volume, host string) error {
	if volume != "unlocked" {
		s.service.notify(SandboxUnlocking, s.box.Name)
	}
	input := struct {
		MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
		MonitorHostKey      string `json:"monitor_host_key"`
		DiskKey             b64u   `json:"disk_key"`
		AllowInitialize     bool   `json:"allow_initialize"`
	}{s.keys.monitorIdentitySeed, host, s.keys.storageKey, true}
	var status sandboxStatus
	if err := s.owner.call(ctx, sandboxEnrollCommand, input, &status); err != nil {
		return fmt.Errorf("%w; rerun `tinfoil sandbox start %s` to reconcile", err, s.box.Name)
	}
	if status.Volume != "unlocked" {
		return fmt.Errorf("sandbox %s workspace is still %s; rerun `tinfoil sandbox start %s`", s.box.Name, status.Volume, s.box.Name)
	}
	s.service.notify(SandboxPrepared, s.box.Name)
	return nil
}

func monitorIdentity(seed []byte) string {
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, _ := ssh.NewPublicKey(private.Public())
	return authorizedKeyLine(public)
}

func authorizedKeyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

type sandboxOwner struct {
	request  func(method, path string, input, out any) error
	instance string
	dial     func(context.Context) (*ssh.Client, error)
	expires  time.Time
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func (o *sandboxOwner) attest(domain, source string, verifier Verifier) (VerifiedHost, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return VerifiedHost{}, err
	}
	input := struct {
		InstanceID string `json:"instance_id"`
		Nonce      string `json:"nonce"`
	}{o.instance, hex.EncodeToString(nonce)}
	var reply relayReply
	if err := o.request(http.MethodPost, "/sandboxes/relay", input, &reply); err != nil {
		return VerifiedHost{}, err
	}
	if reply.Status != http.StatusOK {
		return VerifiedHost{}, fmt.Errorf("sandbox attestation returned HTTP %d", reply.Status)
	}
	doc, err := keybundle.DecodeBase64URL(reply.Body, -1)
	if err != nil {
		return VerifiedHost{}, err
	}
	verified, err := verifier.RelayHost(domain, source, doc, nonce)
	if err != nil {
		return VerifiedHost{}, err
	}
	o.expires = verified.Expires
	return verified, nil
}

// The inner SSH connection owns and closes its Monitor device connection.
type sandboxRouteConn struct {
	net.Conn
	client *ssh.Client
}

func (c *sandboxRouteConn) Close() error {
	return errors.Join(c.Conn.Close(), c.client.Close())
}

func (m *Monitor) dialSandbox(ctx context.Context, host ssh.PublicKey) (net.Conn, error) {
	device, err := loadSigner(filepath.Join(m.dir, monitorDeviceKeyName))
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: ConnectTimeout}).DialContext(ctx, "tcp", m.address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, err := Connect(conn, m.domain, m.hostKey, device, monitorSSHUser)
	if err != nil {
		return nil, err
	}
	route, err := client.DialContext(ctx, "tcp", net.JoinHostPort(routeName(host), strconv.Itoa(defaultSSHPort)))
	if err != nil {
		client.Close()
		return nil, err
	}
	return &sandboxRouteConn{Conn: route, client: client}, nil
}

func (s *Sandbox) dial(ctx context.Context) (*ssh.Client, error) {
	if !time.Now().Before(s.expires) {
		return nil, errors.New("sandbox attestation expired; verify it again before unlocking")
	}
	var conn net.Conn
	var err error
	if s.monitor != nil {
		conn, err = s.monitor.dialSandbox(ctx, s.profile.HostKey)
	} else {
		address := net.JoinHostPort(s.profile.HostName, strconv.Itoa(s.profile.Port))
		conn, err = (&net.Dialer{Timeout: ConnectTimeout}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	return Connect(conn, s.box.Domain, s.profile.HostKey, s.keys.signer, sandboxLoginUser)
}

func (o *sandboxOwner) call(ctx context.Context, command string, input, out any) error {
	ctx, cancel := context.WithDeadline(ctx, o.expires)
	defer cancel()
	var body []byte
	if input != nil {
		var err error
		if body, err = json.Marshal(input); err != nil {
			return err
		}
		defer clear(body)
	}
	reply, err := SendCommand(ctx, o.dial, command, body)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(reply), out)
}

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + sandboxRouteSuffix
}

func (s *Sandbox) unlockDirect(ctx context.Context) error {
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	volume, err := SendCommand(ctx, s.dial, "/usr/local/bin/workspace-unlock --status", nil)
	if err != nil {
		return fmt.Errorf("workspace status: %w", err)
	}
	switch volume {
	case "unlocked":
		return nil
	case "locked":
	default:
		return fmt.Errorf("unexpected workspace status %q", volume)
	}
	if s.keys.storageKey == nil {
		if err := s.keys.generateUMKKeys("sandbox", s.box.OwnerPublicKey, s.binding); err != nil {
			return err
		}
	}
	s.service.notify(SandboxUnlocking, s.box.Name)
	if _, err := SendCommand(ctx, s.dial, "/usr/local/bin/workspace-unlock --initialize", s.keys.storageKey); err != nil {
		return fmt.Errorf("unlock workspace: %w; retry with `tinfoil sandbox start %s`", err, s.box.Name)
	}
	return nil
}

func (s *Sandbox) Close()                     { s.close() }
func (s *Sandbox) Connection() ConnectionInfo { return s.profile }
