package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
)

const (
	sandboxAgentKeyName    = "agent_ed25519"
	sandboxBindingName     = "monitor.json"
	sandboxEnrolledKeyName = "enrolled_host_key"

	sandboxConfigIdentity = "tinfoil/containers"
	sandboxTemplateBase   = "https://raw.githubusercontent.com"

	sandboxAttestationPath     = "/.well-known/tinfoil-attestation"
	maxSandboxAttestationBytes = 32 << 20

	// Monitor routes to a sandbox boot by a name derived from its SSH host key.
	sandboxRouteSuffix = ".sandbox.invalid"
	// Monitor ignores the SSH user; only the device key authorizes routes.
	monitorSSHUser    = "device"
	monitorJumpSuffix = ".monitor"

	monitorDialTimeout    = 10 * time.Second
	sandboxEnrollAttempts = 3
)

type sandboxBinding struct {
	Scope   accountScope `json:"scope"`
	Monitor string       `json:"monitor"`
}

// Native SSH uses the public endpoint; the sandbox uses its allowed peer endpoint.
type sandboxAccess struct {
	Contained          bool   `json:"contained"`
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	SandboxSource      string `json:"sandbox_source"`
	SandboxKey         string `json:"sandbox_key"`
	MonitorName        string `json:"monitor_name"`
	MonitorDomain      string `json:"monitor_domain"`
	MonitorIP          string `json:"monitor_ip"`
	MonitorPort        int    `json:"monitor_port"`
	SandboxMonitorIP   string `json:"sandbox_monitor_ip"`
	SandboxMonitorPort int    `json:"sandbox_monitor_port"`
	MonitorSource      string `json:"monitor_source"`
}

type monitorAgentConfig struct {
	Domain   string `json:"domain"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	HostKey  string `json:"host_key"`
	Identity string `json:"identity"`
}

func sandboxAccessFor(name string) (*sandboxAccess, error) {
	client, err := authedClient()
	if err != nil {
		return nil, err
	}
	box, err := getSandbox(name)
	if err != nil {
		return nil, err
	}
	var row containerView
	if _, err := client.do("GET", pathf("/api/containers/%s", box.ContainerID), nil, nil, &row); err != nil {
		return nil, err
	}
	access := &sandboxAccess{}
	if row.NetworkPolicy == nil {
		return access, nil
	}
	if row.NetworkPolicy.EgressMode == "unrestricted" || row.NetworkPolicy.Public || len(row.NetworkPolicy.Egress) != 1 || row.NetworkPolicy.Egress[0].Port != 22 {
		return nil, fmt.Errorf("sandbox network policy does not name one SSH peer")
	}
	var peer containerView
	if _, err := client.do("GET", pathf("/api/containers/%s", row.NetworkPolicy.Egress[0].ContainerID), nil, nil, &peer); err != nil {
		return nil, err
	}
	var network struct {
		Egress []struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"egress"`
	}
	if _, err := client.do("GET", pathf("/api/containers/%s/network", row.ID), nil, nil, &network); err != nil {
		return nil, err
	}
	if len(network.Egress) != 1 || peer.SSHPort == 0 {
		return nil, fmt.Errorf("peer is unavailable")
	}
	key, verified, err := privateSandboxClient(*box)
	if err != nil {
		return nil, err
	}
	verified.CloseIdleConnections()
	// The sandbox endpoint may be a local guest or a remote published SSH port.
	addresses, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", peer.Domain)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("peer domain has no address")
	}
	access = &sandboxAccess{Contained: true, Name: name, Domain: box.Domain, SandboxSource: "tinfoil/containers@" + storageHash([]byte(row.Config)) + "@sha256:" + storageHash([]byte(row.Config)), SandboxKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), MonitorName: peer.Name, MonitorDomain: peer.Domain, MonitorIP: addresses[0].String(), MonitorPort: peer.SSHPort, SandboxMonitorIP: network.Egress[0].IP, SandboxMonitorPort: network.Egress[0].Port, MonitorSource: "tinfoil/containers@" + storageHash([]byte(peer.Config)) + "@sha256:" + storageHash([]byte(peer.Config))}
	return access, nil
}

func (a *sandboxAccess) check(box sandboxView, monitor monitorProfile) (ssh.PublicKey, error) {
	repo, revision, digest, sourceErr := verify.ParseReference(a.SandboxSource)
	key, _, _, _, keyErr := ssh.ParseAuthorizedKey([]byte(a.SandboxKey))
	switch {
	case a.Name != box.ID || a.Domain != box.Domain:
		return nil, fmt.Errorf("sandbox access names %s at %s", a.Name, a.Domain)
	case a.MonitorName != monitor.Name || a.MonitorDomain != monitor.Domain || a.MonitorSource != monitor.Source:
		return nil, fmt.Errorf("%s is bound to a Monitor other than the one this device verified as %s", box.ID, monitor.Name)
	case sourceErr != nil || repo != sandboxConfigIdentity || digest == "" || revision != digest:
		return nil, fmt.Errorf("sandbox source %q is not a published sandbox config", a.SandboxSource)
	case keyErr != nil:
		return nil, fmt.Errorf("%s reported no usable boot key", box.ID)
	case !validMonitorEndpoint(a.MonitorIP, a.MonitorPort) || !validMonitorEndpoint(a.SandboxMonitorIP, a.SandboxMonitorPort):
		return nil, fmt.Errorf("%s has no usable Monitor endpoint", box.ID)
	}
	return key, nil
}

func validMonitorEndpoint(ip string, port int) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil && port >= 1 && port <= maxConnectionPort
}

// Generate keys only before binding; bound sandboxes must retain their keys.
func containedKeys(name string, binding sandboxBinding, create bool) (*sandboxKeys, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return nil, err
	}
	switch err := bindSandbox(dir, binding, false); {
	case err == nil:
		return loadContainedKeys(dir)
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	case !create:
		return nil, fmt.Errorf("this device has no keys for %s; restore them with `tinfoil monitor import FILE`", name)
	}
	// Creation makes the agent key first, and an uncontained sandbox has none.
	if _, err := os.Stat(filepath.Join(dir, sandboxAgentKeyName)); errors.Is(err, os.ErrNotExist) {
		for _, file := range []string{sandboxDiskKeyName, sandboxSSHKeyName} {
			if _, err := os.Stat(filepath.Join(dir, file)); err == nil {
				return nil, fmt.Errorf("%s holds the keys of an earlier sandbox named %s; move it aside to create this one", dir, name)
			}
		}
	}
	if err := prepareStorageDirectory(dir); err != nil {
		return nil, err
	}
	if _, err := ensureSSHKey(filepath.Join(dir, sandboxAgentKeyName)); err != nil {
		return nil, err
	}
	if _, err := ensureSandboxKeys(name); err != nil {
		return nil, err
	}
	if err := bindSandbox(dir, binding, true); err != nil {
		return nil, err
	}
	return loadContainedKeys(dir)
}

func loadContainedKeys(dir string) (*sandboxKeys, error) {
	keys := &sandboxKeys{dir: dir, sshKeyPath: filepath.Join(dir, sandboxSSHKeyName)}
	disk, err := os.ReadFile(filepath.Join(dir, sandboxDiskKeyName))
	if err == nil {
		keys.diskKey = strings.TrimSpace(string(disk))
		if decoded, decodeErr := base64.StdEncoding.DecodeString(keys.diskKey); decodeErr != nil || len(decoded) != sandboxDiskKeyBytes {
			err = fmt.Errorf("%s does not hold base64 for a %d-byte workspace key", filepath.Join(dir, sandboxDiskKeyName), sandboxDiskKeyBytes)
		}
	}
	if err == nil {
		keys.publicKey, err = loadSSHKey(keys.sshKeyPath)
	}
	if err == nil {
		keys.agentKey, err = loadSSHKey(filepath.Join(dir, sandboxAgentKeyName))
	}
	if err != nil {
		return nil, fmt.Errorf("%w; restore keys with `tinfoil monitor import FILE`", err)
	}
	return keys, nil
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

// Register before creation. Resume only a running sandbox bound to these keys.
func registerSandboxAgent(name, monitor string) (resume bool, err error) {
	scope, client, err := currentScope()
	if err != nil {
		return false, err
	}
	binding := sandboxBinding{scope, monitor}
	var missing *cpError
	if box, err := getSandbox(name); err == nil {
		dir, err := sandboxKeyDir(name)
		if err != nil {
			return false, err
		}
		if err := bindSandbox(dir, binding, false); errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("sandbox %s exists but this device holds no keys; restore them with `tinfoil monitor import FILE`", name)
		} else if err != nil {
			return false, err
		}
		switch box.State {
		case sandboxStateRunning:
		case sandboxStateStopped:
			return false, fmt.Errorf("sandbox %s already exists and is stopped; start it with `tinfoil sandbox start %s`", name, name)
		case sandboxStatePending:
			return false, fmt.Errorf("sandbox %s already exists and is still booting; run this again once it is running", name)
		default:
			return false, fmt.Errorf("sandbox %s already exists and is %s; recover it with `tinfoil sandbox restart %s`", name, box.State, name)
		}
		peer, err := containerNamed(client, monitor)
		if err != nil {
			return false, err
		}
		var row containerView
		if _, err = client.do("GET", pathf("/api/containers/%s", box.ContainerID), nil, nil, &row); err != nil {
			return false, err
		}
		if row.NetworkPolicy == nil || row.NetworkPolicy.EgressMode == "unrestricted" || row.NetworkPolicy.Public || len(row.NetworkPolicy.Egress) != 1 || row.NetworkPolicy.Egress[0] != (containerPeer{peer.ID, 22}) {
			return false, fmt.Errorf("sandbox %s already exists and is not contained by Monitor %s", name, monitor)
		}
		return true, nil
	} else if !errors.As(err, &missing) || missing.Status != http.StatusNotFound {
		return false, err
	}
	keys, err := containedKeys(name, binding, true)
	if err != nil {
		return false, err
	}
	m, err := openMonitor(scope, monitor, false)
	if err != nil {
		return false, err
	}
	if err := m.deviceRoutes(); err != nil {
		return false, err
	}
	return false, m.ensureIdentity(sandboxIdentityPrefix+name, keys.agentKey, false)
}

type containedSandbox struct {
	monitor *monitorSession
	keys    *sandboxKeys
	bootKey ssh.PublicKey
}

func openContained(box sandboxView, access *sandboxAccess) (*containedSandbox, error) {
	scope, _, err := currentScope()
	if err != nil {
		return nil, err
	}
	m, err := openMonitor(scope, access.MonitorName, false)
	if err != nil {
		return nil, err
	}
	if err := m.deviceRoutes(); err != nil {
		return nil, err
	}
	bootKey, err := access.check(box, m.profile)
	if err != nil {
		return nil, err
	}
	keys, err := containedKeys(box.ID, sandboxBinding{scope, access.MonitorName}, false)
	if err != nil {
		return nil, err
	}
	return &containedSandbox{monitor: m, keys: keys, bootKey: bootKey}, nil
}

// Send enrollment over the private connection after verifying the guest.
func enrollContained(box sandboxView, access *sandboxAccess) error {
	dir, err := sandboxKeyDir(box.ID)
	if err != nil {
		return err
	}
	enrolledPath := filepath.Join(dir, sandboxEnrolledKeyName)
	if enrolled, _ := os.ReadFile(enrolledPath); sameSSHKey(string(enrolled), access.SandboxKey) {
		fmt.Fprintf(os.Stderr, "Sandbox %s is already enrolled.\n", box.ID)
		return nil
	}
	c, err := openContained(box, access)
	if err != nil {
		return err
	}
	attested, httpClient, err := privateSandboxClient(box)
	if err != nil {
		return err
	}
	defer httpClient.CloseIdleConnections()
	identity, err := os.ReadFile(filepath.Join(c.keys.dir, sandboxAgentKeyName))
	if err != nil {
		return err
	}
	c.keys.monitor = &monitorAgentConfig{Domain: c.monitor.profile.Domain, IP: access.SandboxMonitorIP, Port: access.SandboxMonitorPort, HostKey: c.monitor.profile.HostKey, Identity: string(identity)}
	if err := sendEnrollment(httpClient, "https://"+box.Domain+sandboxEnrollPath, c.keys); err != nil {
		return fmt.Errorf("%w; retry with `tinfoil sandbox enroll %s`", err, box.ID)
	}
	if err := writeAtomic(enrolledPath, ssh.MarshalAuthorizedKey(attested)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Enrolled %s with the keys in %s\n", box.ID, c.keys.dir)
	return nil
}

// Verify fresh evidence and the shim TLS key before returning an enrollment client.
func attestConnection(dial func(context.Context, string, string) (net.Conn, error), host, source string) (ssh.PublicKey, *http.Client, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, nil, err
	}
	fetch := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}, Timeout: sandboxEnrollTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer fetch.CloseIdleConnections()
	resp, err := fetch.Get("https://" + host + sandboxAttestationPath + "?nonce=" + hex.EncodeToString(nonce))
	if err != nil {
		return nil, nil, fmt.Errorf("fetching the attestation of %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetching the attestation of %s: %s", host, resp.Status)
	}
	doc, err := io.ReadAll(io.LimitReader(resp.Body, maxSandboxAttestationBytes+1))
	if err == nil && len(doc) > maxSandboxAttestationBytes {
		err = fmt.Errorf("it exceeds %d bytes", maxSandboxAttestationBytes)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading the attestation of %s: %w", host, err)
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, nil, err
	}
	verified, err := verifier.VerifyV3(doc, nonce, source)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying %s: %w", host, err)
	}
	key, err := endorsedHostKey(host, verified)
	if err != nil {
		return nil, nil, err
	}
	fingerprint, err := verified.TLSPublicKeyFP()
	if err != nil {
		return nil, nil, err
	}
	if resp.TLS == nil {
		return nil, nil, errors.New("shim supplied no TLS key")
	}
	if err := pinnedTLS(fingerprint)(*resp.TLS); err != nil {
		return nil, nil, fmt.Errorf("shim TLS: %w", err)
	}
	pinned := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: pinnedTLS(fingerprint)}}, Timeout: sandboxEnrollTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pinned.Transport = freshAttestation{pinned.Transport.(*http.Transport), verified.FreshnessExpiresAt}
	return key, pinned, nil
}

// Check freshness on every request, including reused TLS connections.
type freshAttestation struct {
	*http.Transport
	expires time.Time
}

func (f freshAttestation) RoundTrip(r *http.Request) (*http.Response, error) {
	if !time.Now().Before(f.expires) {
		return nil, errors.New("the sandbox attestation has no unexpired freshness; run the command again to verify it anew")
	}
	return f.Transport.RoundTrip(r)
}

// Enrollment can lose its reply during the systemd handoff. Retry the same body.
func sendEnrollment(httpClient *http.Client, endpoint string, keys *sandboxKeys) error {
	for attempt := 1; ; attempt++ {
		err := postEnrollment(httpClient, endpoint, keys)
		var lost *url.Error
		if err == nil || !errors.As(err, &lost) || attempt == sandboxEnrollAttempts {
			return err
		}
		fmt.Fprintf(os.Stderr, "Enrollment reply lost: %v. Reconnecting and retrying.\n", lost.Err)
	}
}

func containedProfile(box sandboxView, access *sandboxAccess) (sshProfile, error) {
	c, err := openContained(box, access)
	if err != nil {
		return sshProfile{}, err
	}
	if enrolled, _ := os.ReadFile(filepath.Join(c.keys.dir, sandboxEnrolledKeyName)); !sameSSHKey(string(enrolled), access.SandboxKey) {
		return sshProfile{}, fmt.Errorf("this device has not enrolled the current boot of %s; enroll it with `tinfoil sandbox enroll %s`", box.ID, box.ID)
	}
	m := c.monitor
	return sshProfile{name: box.ID, hostName: routeName(c.bootKey), port: defaultSSHPort, user: sandboxLoginUser, identityFile: c.keys.sshKeyPath, hostKey: c.bootKey, hostKeyAlias: box.Domain,
		jump: &sshProfile{name: box.ID + monitorJumpSuffix, hostName: access.MonitorIP, port: access.MonitorPort, user: monitorSSHUser, identityFile: filepath.Join(m.dir, monitorDeviceKeyName), hostKey: m.hostKey, hostKeyAlias: m.profile.Domain}}, nil
}

func attestSandboxSSH(cmd *cobra.Command) error {
	for _, flag := range []string{"name", "ssh-host", "user", "ssh-port", "identity"} {
		if cmd.Flags().Changed(flag) {
			return fmt.Errorf("--%s does not apply to --sandbox", flag)
		}
	}
	name, err := sandboxName(attestSSHSandbox)
	if err != nil {
		return err
	}
	box, err := getSandbox(name)
	if err != nil {
		return err
	}
	if box.State != sandboxStateRunning {
		return fmt.Errorf("sandbox %s is %s; start it with `tinfoil sandbox start %s`", name, box.State, name)
	}
	access, err := sandboxAccessFor(name)
	if err != nil {
		return err
	}
	if !access.Contained {
		return fmt.Errorf("%s is not bound to a Monitor", name)
	}
	profile, err := containedProfile(*box, access)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Attestation successful.")
	if !attestSSHInstall {
		fmt.Printf("%s\n# ~/.ssh/tinfoil/%s.known_hosts\n%s", profile.render(), profile.name, profile.pin())
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return installSandboxAlias(profile, home)
}

func containedTarget(box sandboxView, access *sandboxAccess) (*tunnelTarget, error) {
	profile, err := containedProfile(box, access)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	if err := installSandboxAlias(profile, home); err != nil {
		return nil, err
	}
	return &tunnelTarget{name: box.ID, host: box.ID, sshConfig: filepath.Join(home, ".ssh", "tinfoil", box.ID+".conf")}, nil
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
	return bytes.Contains(existing, []byte("\n  IdentityFile "+identityFile+"\n")), err
}

// Remove access and the SSH profile, retaining recovery keys.
func forgetContainedSandbox(name string) (bool, error) {
	dir, err := sandboxKeyDir(name)
	if err != nil {
		return false, err
	}
	var binding sandboxBinding
	if err := readStorageJSON(filepath.Join(dir, sandboxBindingName), &binding); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	scope, _, err := currentScope()
	if err != nil || binding.Scope != scope {
		return false, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return true, err
	}
	if owned, err := ownsSSHProfile(home, name, filepath.Join(dir, sandboxSSHKeyName)); err == nil && owned {
		for _, file := range []string{name + ".conf", name + ".known_hosts"} {
			if err := os.Remove(filepath.Join(home, ".ssh", "tinfoil", file)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return true, err
			}
		}
	}
	signer, err := loadSigner(filepath.Join(dir, sandboxAgentKeyName))
	if err != nil {
		return true, err
	}
	m, err := openMonitor(scope, binding.Monitor, false)
	if err == nil {
		err = m.removeIdentity(sandboxIdentityPrefix+name, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	}
	if err != nil {
		return true, fmt.Errorf("its Monitor identity %s%s may remain: %w", sandboxIdentityPrefix, name, err)
	}
	return true, nil
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

func privateSandboxClient(box sandboxView) (ssh.PublicKey, *http.Client, error) {
	client, err := authedClient()
	if err != nil {
		return nil, nil, err
	}
	source, err := sandboxSource(client, box, sandboxTemplateBase)
	if err != nil {
		return nil, nil, err
	}
	return attestConnection(privateDialer(client, box.ContainerID, 443), box.Domain, source)
}

// Reproduce the measured config with this device's owner key before trusting it.
func sandboxSource(client *cpClient, box sandboxView, templateBase string) (string, error) {
	owner, err := loadDiskKey(box.ID)
	if err != nil {
		return "", err
	}
	defer clear(owner)
	var row containerView
	if _, err := client.do("GET", pathf("/api/containers/%s", box.ContainerID), nil, nil, &row); err != nil {
		return "", err
	}
	if row.Repo != sandboxRepo() || row.Domain != box.Domain || row.CurrentTag == "" {
		return "", errors.New("unexpected sandbox configuration")
	}
	location := templateBase + "/" + row.Repo + "/" + url.PathEscape(row.CurrentTag) + "/tinfoil-config.yml"
	template, err := fetchUpdateData(context.Background(), &http.Client{Timeout: sandboxEnrollTimeout}, location, version, maxSandboxAttestationBytes)
	if err != nil {
		return "", fmt.Errorf("fetching sandbox template: %w", err)
	}
	variables, err := parseKeyValues(sandboxVariables)
	if err != nil {
		return "", err
	}
	return verifySandboxConfig(row, storageHash(owner), template, variables)
}

func verifySandboxConfig(row containerView, ownerDigest string, template []byte, variables map[string]string) (string, error) {
	if variables == nil {
		variables = make(map[string]string)
	}
	variables[sandboxOwnerEnv] = ownerDigest
	rendered, err := renderTemplateEnv(template, variables)
	if err != nil {
		return "", fmt.Errorf("render sandbox template: %w", err)
	}
	if !bytes.Equal([]byte(row.Config), rendered) {
		return "", errors.New("sandbox measured config does not match the template, --variable values and this device's owner key")
	}
	digest := storageHash(rendered)
	return sandboxConfigIdentity + "@" + digest + "@sha256:" + digest, nil
}
