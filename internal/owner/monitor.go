package owner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"golang.org/x/crypto/ssh"
)

const (
	MonitorRepo     = "tinfoilsh/confidential-agent-monitor"
	MonitorOwnerEnv = "MONITOR_OWNER_PUBLIC_KEY"

	// A relayed sandbox attestation is up to 32 MiB before base64 and JSON.
	maxMonitorReplyBytes = 48 << 20

	monitorRequestTimeout = time.Minute
)

var monitorBucketPattern = regexp.MustCompile(`^s3://[a-z0-9.-]+\?prefix=containers%2F([0-9a-f]{64})%2F[A-Za-z0-9-]+%2F&region=[a-z0-9-]+$`)

func bucketOwnedBy(bucket, account, user string) bool {
	owner := "org:" + account
	if account == "personal" {
		owner = "user:" + user
	}
	match := monitorBucketPattern.FindStringSubmatch(bucket)
	digest := sha256.Sum256([]byte(owner))
	return match != nil && match[1] == hex.EncodeToString(digest[:])
}

type Monitor struct {
	service *Service
	client  *ssh.Client
	request func(method, path string, input, out any) error
	dir     string
	domain  string
	address string
	hostKey ssh.PublicKey
	view    monitorView
	keys    *resourceKeys
}

type monitorView struct {
	Generation uint64 `json:"generation"`
	HostKey    string `json:"host_key"`
	Config     struct {
		Identities map[string]struct {
			Key string `json:"key"`
		} `json:"identities"`
	} `json:"config"`
}

func (s *Service) ConnectMonitor(ctx context.Context, scope Scope, cp *controlplane.Client, row *Workload, restoreDevice bool, verifier Verifier) (_ *Monitor, err error) {
	if err := requireRunningConnection("Perimeter", row.Container); err != nil {
		return nil, err
	}
	if row.SSHPort < 1 || row.SSHPort > maxConnectionPort {
		return nil, errors.New("Perimeter has no published SSH port")
	}
	s.notify(MonitorRunning, row.Name)
	bucket := row.Environment["TINFOIL_STORAGE_BUCKET"]
	if len(bucket) > keybundle.MaxBucketChars || !bucketOwnedBy(bucket, scope.Account(), scope.UserID) {
		return nil, errors.New("Perimeter storage does not belong to this account")
	}
	if row.Environment[MonitorOwnerEnv] != row.OwnerPublicKey {
		return nil, errors.New("Perimeter's measured owner is not its owner key")
	}
	dir, err := s.monitorRecord(scope, row)
	if err != nil {
		return nil, err
	}
	m := &Monitor{service: s, dir: dir, domain: row.Domain, address: net.JoinHostPort(row.Domain, strconv.Itoa(row.SSHPort))}
	defer func() {
		if err != nil {
			m.close()
		}
	}()
	binding := mkBinding{Account: scope.Account(), ContainerID: row.ID, Bucket: &bucket}
	if m.keys, err = s.resolveResourceKeys(ctx, cp, scope, row.Container, "monitor", binding, dir, true); err != nil {
		return nil, err
	}
	if _, err := UpdateProfile(dir, func(p *Profile) error {
		p.Generation, p.Custody = max(p.Generation, m.keys.minGeneration), m.keys.mode
		return nil
	}); err != nil {
		return nil, err
	}
	device := func() error { _, err := ensureSSHKey(filepath.Join(dir, MonitorDeviceKeyName)); return err }
	if m.keys.mode == "tmk" {
		err = s.activeGrant(device)
	} else {
		err = device()
	}
	if err != nil {
		return nil, err
	}
	if m.hostKey, err = verifier.MonitorHost(row.Domain, row.Source); err != nil {
		return nil, err
	}
	if _, err := UpdateProfile(dir, func(p *Profile) error {
		p.HostKey, p.Address = authorizedKeyLine(m.hostKey), m.address
		return nil
	}); err != nil {
		return nil, err
	}
	s.notify(MonitorVerified, row.Name)
	s.notify(MonitorConnecting, row.Name)
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", m.address)
	if err != nil {
		return nil, err
	}
	if m.client, err = Connect(conn, row.Domain, m.hostKey, m.keys.signer, "owner"); err != nil {
		return nil, err
	}
	m.request = func(method, path string, input, out any) error {
		return monitorOwnerRequest(m.client, m.dir, method, path, input, out)
	}
	if err := m.open(ctx, row.Name, row.OwnerPublicKey, binding, restoreDevice); err != nil {
		return nil, err
	}
	s.notify(MonitorUnlocked, row.Name)
	return m, nil
}

func (m *Monitor) open(ctx context.Context, name, owner string, binding mkBinding, restoreDevice bool) error {
	var health struct {
		State string `json:"state"`
	}
	if err := m.request(http.MethodGet, "/healthz", nil, &health); err != nil {
		return err
	}
	if health.State != "present" && health.State != "absent" {
		return fmt.Errorf("Perimeter %s does not implement the current owner protocol; update it before opening", name)
	}
	if m.keys.storageKey == nil {
		if health.State != "absent" {
			return fmt.Errorf("Perimeter %s has saved state, but this machine has no storage key for it; restore its UMK keys file %s", name, m.keys.umkPath)
		}
		if err := m.keys.generateUMKKeys("monitor", owner, binding); err != nil {
			return err
		}
	}
	m.service.notify(MonitorUnlocking, name)
	if err := m.unlock(restoreDevice); err != nil {
		return fmt.Errorf("unlock Perimeter: %w", err)
	}
	m.checkpoint(ctx)
	return nil
}

func (m *Monitor) close() {
	if m.client != nil {
		m.client.Close()
	}
	if m.keys != nil {
		m.keys.close()
	}
}

func (m *Monitor) unlock(restoreDevice bool) error {
	var profile Profile
	if err := statefile.ReadJSON(filepath.Join(m.dir, ProfileFile), &profile); err != nil {
		return err
	}
	input := struct {
		Generation uint64 `json:"generation"`
		StorageKey []byte `json:"storage_key"`
		DeviceKey  string `json:"device_key,omitempty"`
	}{Generation: profile.Generation, StorageKey: m.keys.storageKey}
	if restoreDevice {
		device, err := loadSSHKey(filepath.Join(m.dir, MonitorDeviceKeyName))
		if err != nil {
			return fmt.Errorf("restore Perimeter device key: %w", err)
		}
		input.DeviceKey = device
	}
	var view monitorView
	if err := m.request(http.MethodPost, "/unlock", input, &view); err != nil {
		return err
	}
	reported, _, _, _, err := ssh.ParseAuthorizedKey([]byte(view.HostKey))
	if err != nil || !bytes.Equal(reported.Marshal(), m.hostKey.Marshal()) {
		return errors.New("Perimeter reports a host key other than its attested one")
	}
	m.view = view
	return nil
}

func (m *Monitor) authorizes(agent string) bool {
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(agent))
	for _, identity := range m.view.Config.Identities {
		key, _, _, _, keyErr := ssh.ParseAuthorizedKey([]byte(identity.Key))
		if err == nil && keyErr == nil && bytes.Equal(key.Marshal(), want.Marshal()) {
			return true
		}
	}
	return false
}

func (m *Monitor) enrollAgent(ctx context.Context, name, agent string) error {
	var view monitorView
	if err := m.request(http.MethodPost, "/enroll", map[string]any{name: map[string]any{"key": agent}}, &view); err != nil {
		return err
	}
	m.view = view
	m.checkpoint(ctx)
	return nil
}

func (m *Monitor) checkpoint(ctx context.Context) {
	if m.keys.mk == nil {
		return
	}
	var profile Profile
	err := statefile.ReadJSON(filepath.Join(m.dir, ProfileFile), &profile)
	if err == nil && profile.Generation <= m.keys.minGeneration {
		return
	}
	if err == nil {
		_, err = m.keys.mk.update(ctx, func(p *mkPayload) error {
			r := findKey(p, func(r *mkResource) bool { return r.KeyID == m.keys.keyID })
			if r == nil || r.MinGeneration == nil {
				return errors.New("the Perimeter key is no longer in your key bundle")
			}
			*r.MinGeneration = max(*r.MinGeneration, profile.Generation)
			return nil
		})
	}
	if err != nil {
		if m.service.Notify != nil {
			m.service.Notify(Event{Stage: MonitorCheckpointFailed, Generation: profile.Generation, Err: err})
		}
		return
	}
	m.keys.minGeneration = profile.Generation
}

func (s *Service) monitorRecord(scope Scope, row *Workload) (string, error) {
	dir, err := resourceDirectory(s.ConfigPath, scope, row.ID, row.Name)
	if err != nil {
		return "", err
	}
	_, err = UpdateProfile(dir, func(p *Profile) error {
		if p.Domain != "" && p.Domain != row.Domain || p.ContainerID != "" && p.ContainerID != row.ID ||
			p.Owner != "" && (p.Owner != row.Environment[MonitorOwnerEnv] || p.Storage != row.Environment["TINFOIL_STORAGE_BUCKET"]) {
			return errors.New("Perimeter identity or storage binding changed")
		}
		p.Domain, p.ContainerID, p.Owner, p.Storage = row.Domain, row.ID, row.Environment[MonitorOwnerEnv], row.Environment["TINFOIL_STORAGE_BUCKET"]
		return nil
	})
	return dir, err
}

// Owner API calls use the UI's attested channel and persist its generation acknowledgments.
func monitorOwnerRequest(client *ssh.Client, dir, method, path string, input, out any) error {
	var data []byte
	if input != nil {
		var err error
		if data, err = json.Marshal(input); err != nil {
			return err
		}
		defer clear(data)
	}
	timer := time.AfterFunc(monitorRequestTimeout, func() { client.Close() })
	defer timer.Stop()
	token := panelToken()
	ch, err := OpenChannel(client, dir, "owner.perimeter", token)
	if err != nil {
		return err
	}
	defer ch.Close()
	req, err := http.NewRequest(method, "http://owner.perimeter/api"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Tinfoil-Session", token)
	if err := req.Write(ch); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(ch), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxMonitorReplyBytes+1))
	if err != nil {
		return err
	}
	if len(reply) > maxMonitorReplyBytes {
		return errors.New("Perimeter response is too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Perimeter: %s: %s", resp.Status, controlplane.ErrorMessage(reply))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(reply, out)
}

func panelToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.RawURLEncoding.EncodeToString(token)
}

func (m *Monitor) Close() { m.close() }

func (m *Monitor) ValidateSandboxCustody(row controlplane.Container) error {
	if m.keys.mode == "umk" && row.OwnerKeyMode == "tmk" {
		return fmt.Errorf("a UMK Perimeter cannot serve the synced bunker %s", row.Name)
	}
	return nil
}

func (m *Monitor) OpenChannel(host, token string) (ssh.Channel, error) {
	return OpenChannel(m.client, m.dir, host, token)
}

func (m *Monitor) ForwardPanel(ctx context.Context, listener net.Listener, token string) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { m.client.Wait(); stop() }()
	go func() { <-ctx.Done(); listener.Close(); m.client.Close() }()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer local.Close()
			stop := context.AfterFunc(ctx, func() { local.Close() })
			defer stop()
			remote, err := m.OpenChannel(listener.Addr().String(), token)
			if err != nil {
				return
			}
			defer remote.Close()
			done := make(chan struct{})
			go func() { io.Copy(remote, local); remote.CloseWrite(); close(done) }()
			io.Copy(local, remote)
			local.Close()
			remote.Close()
			<-done
		}()
	}
}
