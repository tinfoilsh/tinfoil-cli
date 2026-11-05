package main

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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	monitorRepo     = "tinfoilsh/confidential-agent-monitor"
	monitorOwnerEnv = "MONITOR_OWNER_PUBLIC_KEY"

	monitorDeviceKeyName = "device_ed25519"
	monitorProfileFile   = owner.ProfileFile

	// A relayed sandbox attestation is up to 32 MiB before base64 and JSON.
	maxMonitorReplyBytes = 48 << 20

	monitorRequestTimeout = time.Minute
)

// Monitor names are scoped to an account and control plane.
type accountScope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id,omitempty"`
	UserID          string `json:"user_id"`
	OrgName         string `json:"-"` // Display only; account identity must survive renames.
	UserName        string `json:"-"`
}

// Persist the domain, boot key and minimum generation.
type monitorProfile = owner.Profile

func (s accountScope) account() string {
	if s.OrgID != "" {
		return s.OrgID
	}
	return "personal"
}

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

func newMonitorCommand() *cobra.Command {
	monitorCmd := &cobra.Command{
		Use:     "monitor",
		Aliases: []string{"monitors"},
		Short:   "Manage the Monitor your sandboxes connect through",
	}

	return monitorCmd
}

func currentScope() (accountScope, *cpClient, error) {
	cfg, err := requireAuth()
	if err != nil {
		return accountScope{}, nil, err
	}
	identity, err := authenticatedContext(cfg)
	if err != nil {
		return accountScope{}, nil, err
	}
	scope := accountScope{ControlplaneURL: cfg.ControlplaneURL, UserID: identity.UserID, UserName: identity.UserName}
	if identity.Organization != nil {
		scope.OrgID = identity.Organization.ID
		scope.OrgName = identity.Organization.Name
	}
	if cfg.login != nil && (scope.UserID != cfg.login.UserID || scope.account() != cfg.login.Account) {
		return accountScope{}, nil, errors.New("the API reports a different account than this login; run `tinfoil login` to choose an account")
	}
	return scope, newCPClient(cfg), nil
}

// Serialize updates to preserve boot-key pins and the maximum generation.
func updateProfile(dir string, update func(*monitorProfile) error) (monitorProfile, error) {
	return owner.UpdateProfile(dir, update)
}

type monitorSession struct {
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

func connectMonitorOwner(identityOpts *identityOptions, rootOpts *rootOptions, ctx context.Context, scope accountScope, cp *cpClient, row *workloadTarget, restoreDevice bool) (_ *monitorSession, err error) {
	if err := requireRunningConnection("Monitor", row.containerView); err != nil {
		return nil, err
	}
	if row.SSHPort < 1 || row.SSHPort > maxConnectionPort {
		return nil, errors.New("Monitor has no published SSH port")
	}
	fmt.Fprintf(os.Stderr, "Monitor %s: running.\n", row.Name)
	bucket := row.env["TINFOIL_STORAGE_BUCKET"]
	if len(bucket) > maxBucketChars || !bucketOwnedBy(bucket, scope.account(), scope.UserID) {
		return nil, errors.New("Monitor storage does not belong to this account")
	}
	if row.env[monitorOwnerEnv] != row.OwnerPublicKey {
		return nil, errors.New("Monitor's measured owner is not its owner key")
	}
	dir, err := monitorRecord(scope, row)
	if err != nil {
		return nil, err
	}
	m := &monitorSession{dir: dir, domain: row.Domain, address: net.JoinHostPort(row.Domain, strconv.Itoa(row.SSHPort))}
	defer func() {
		if err != nil {
			m.close()
		}
	}()
	binding := mkBinding{Account: scope.account(), ContainerID: row.ID, Bucket: &bucket}
	if m.keys, err = resolveResourceKeys(identityOpts, ctx, cp, scope, row.containerView, "monitor", binding, dir, true); err != nil {
		return nil, err
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error {
		p.Generation, p.Custody = max(p.Generation, m.keys.minGeneration), m.keys.mode
		return nil
	}); err != nil {
		return nil, err
	}
	device := func() error { _, err := ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName)); return err }
	if m.keys.mode == "tmk" {
		err = whileSignedIn(cp.login, device)
	} else {
		err = device()
	}
	if err != nil {
		return nil, err
	}
	if m.hostKey, err = attestedHostKey(rootOpts, row.Domain, row.source, ""); err != nil {
		return nil, err
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error {
		p.HostKey, p.Address = authorizedKeyLine(m.hostKey), m.address
		return nil
	}); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Monitor %s attestation verified.\n", row.Name)
	fmt.Fprintln(os.Stderr, "Connecting to Monitor "+row.Name+" over attested SSH")
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", m.address)
	if err != nil {
		return nil, err
	}
	if m.client, err = connectOwnerSigner(conn, row.Domain, m.hostKey, m.keys.signer, "owner"); err != nil {
		return nil, err
	}
	m.request = func(method, path string, input, out any) error {
		return monitorOwnerRequest(m.client, m.dir, method, path, input, out)
	}
	if err := m.open(ctx, row.Name, row.OwnerPublicKey, binding, restoreDevice); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Monitor %s unlocked.\n", row.Name)
	return m, nil
}

func (m *monitorSession) open(ctx context.Context, name, owner string, binding mkBinding, restoreDevice bool) error {
	var health struct {
		State string `json:"state"`
	}
	if err := m.request(http.MethodGet, "/healthz", nil, &health); err != nil {
		return err
	}
	if health.State != "present" && health.State != "absent" {
		return fmt.Errorf("Monitor %s does not implement the current owner protocol; update it before opening", name)
	}
	if m.keys.storageKey == nil {
		if health.State != "absent" {
			return fmt.Errorf("Monitor %s has saved state, but this machine has no storage key for it; restore its UMK keys file %s", name, m.keys.umkPath)
		}
		if err := m.keys.generateUMKKeys("monitor", owner, binding); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "Unlocking Monitor "+name+" encrypted state")
	if err := m.unlock(restoreDevice); err != nil {
		return fmt.Errorf("unlock Monitor: %w", err)
	}
	m.checkpoint(ctx)
	return nil
}

func (m *monitorSession) close() {
	if m.client != nil {
		m.client.Close()
	}
	if m.keys != nil {
		m.keys.close()
	}
}

func (m *monitorSession) unlock(restoreDevice bool) error {
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(m.dir, monitorProfileFile), &profile); err != nil {
		return err
	}
	input := struct {
		Generation uint64 `json:"generation"`
		StorageKey []byte `json:"storage_key"`
		DeviceKey  string `json:"device_key,omitempty"`
	}{Generation: profile.Generation, StorageKey: m.keys.storageKey}
	if restoreDevice {
		device, err := loadSSHKey(filepath.Join(m.dir, monitorDeviceKeyName))
		if err != nil {
			return fmt.Errorf("restore Monitor device key: %w", err)
		}
		input.DeviceKey = device
	}
	var view monitorView
	if err := m.request(http.MethodPost, "/unlock", input, &view); err != nil {
		return err
	}
	reported, _, _, _, err := ssh.ParseAuthorizedKey([]byte(view.HostKey))
	if err != nil || !bytes.Equal(reported.Marshal(), m.hostKey.Marshal()) {
		return errors.New("Monitor reports a host key other than its attested one")
	}
	m.view = view
	return nil
}

func (m *monitorSession) authorizes(agent string) bool {
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(agent))
	for _, identity := range m.view.Config.Identities {
		key, _, _, _, keyErr := ssh.ParseAuthorizedKey([]byte(identity.Key))
		if err == nil && keyErr == nil && bytes.Equal(key.Marshal(), want.Marshal()) {
			return true
		}
	}
	return false
}

func (m *monitorSession) enrollAgent(ctx context.Context, name, agent string) error {
	var view monitorView
	if err := m.request(http.MethodPost, "/enroll", map[string]any{name: map[string]any{"key": agent}}, &view); err != nil {
		return err
	}
	m.view = view
	m.checkpoint(ctx)
	return nil
}

func (m *monitorSession) checkpoint(ctx context.Context) {
	if m.keys.mk == nil {
		return
	}
	var profile monitorProfile
	err := readStorageJSON(filepath.Join(m.dir, monitorProfileFile), &profile)
	if err == nil && profile.Generation <= m.keys.minGeneration {
		return
	}
	if err == nil {
		_, err = m.keys.mk.update(ctx, func(p *mkPayload) error {
			r := findKey(p, func(r *mkResource) bool { return r.KeyID == m.keys.keyID })
			if r == nil || r.MinGeneration == nil {
				return errors.New("the Monitor key is no longer in your key bundle")
			}
			*r.MinGeneration = max(*r.MinGeneration, profile.Generation)
			return nil
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Monitor generation %d is saved only on this machine; synchronizing it to your key bundle failed: %v\n", profile.Generation, err)
		return
	}
	m.keys.minGeneration = profile.Generation
}

func monitorRecord(scope accountScope, row *workloadTarget) (string, error) {
	dir, err := resourceDir(scope, row.ID, row.Name)
	if err != nil {
		return "", err
	}
	_, err = updateProfile(dir, func(p *monitorProfile) error {
		if p.Domain != "" && p.Domain != row.Domain || p.ContainerID != "" && p.ContainerID != row.ID ||
			p.Owner != "" && (p.Owner != row.env[monitorOwnerEnv] || p.Storage != row.env["TINFOIL_STORAGE_BUCKET"]) {
			return errors.New("Monitor identity or storage binding changed")
		}
		p.Domain, p.ContainerID, p.Owner, p.Storage = row.Domain, row.ID, row.env[monitorOwnerEnv], row.env["TINFOIL_STORAGE_BUCKET"]
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
	ch, err := openOwnerChannel(client, dir, "owner.monitor", token)
	if err != nil {
		return err
	}
	defer ch.Close()
	req, err := http.NewRequest(method, "http://owner.monitor/api"+path, bytes.NewReader(data))
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
		return errors.New("Monitor response is too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Monitor: %s: %s", resp.Status, extractErrorMessage(reply))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(reply, out)
}

// Authenticate only against the SSH host key endorsed by attestation.
func connectOwnerSigner(conn net.Conn, host string, hostKey ssh.PublicKey, signer ssh.Signer, user string) (*ssh.Client, error) {
	return owner.Connect(conn, host, hostKey, signer, user)
}

func openOwnerChannel(client *ssh.Client, dir, host, token string) (ssh.Channel, error) {
	return owner.OpenChannel(client, dir, host, token)
}

func newMonitorOpenCommand(identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions) *cobra.Command {
	command := &cobra.Command{
		Use: "open [id|name]", Short: "Unlock and forward the Monitor UI over attested SSH", Args: cobra.ExactArgs(1),
		Long: "Also restores this device's sandbox connectivity.",
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			fmt.Fprintln(cmd.ErrOrStderr(), "Looking up Monitor "+name)
			scope, cp, err := currentScope()
			if err != nil {
				return err
			}
			row, err := resolveContainerDetail(cp, name)
			if err != nil {
				return err
			}
			target, err := resolveWorkload(rootOpts, trustOpts, *row, monitorRepo, rootOpts.repo)
			if err != nil {
				return err
			}
			m, err := connectMonitorOwner(identityOpts, rootOpts, cmd.Context(), scope, cp, target, true)
			if err != nil {
				return err
			}
			defer m.close()
			for _, failure := range relinkSandboxes(identityOpts, rootOpts, trustOpts, cmd.Context(), scope, cp, m, row.ID) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not re-link %v\n", failure)
			}
			return serveMonitorPanel(cmd, m.client, m.dir, "127.0.0.1:0")
		},
	}
	addTrustDangerousFlag(trustOpts, command)
	return command
}

func panelToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.RawURLEncoding.EncodeToString(token)
}

func serveMonitorPanel(cmd *cobra.Command, client *ssh.Client, dir, address string) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	session := panelToken()
	// Probe the channel contract before printing a URL. A stale generation or
	// incompatible CAM must fail here, without any HTTP fallback.
	fmt.Fprintln(cmd.ErrOrStderr(), "Opening the local Monitor panel")
	probe, err := openOwnerChannel(client, dir, listener.Addr().String(), session)
	if err != nil {
		return err
	}
	probe.Close()
	go func() { client.Wait(); stop() }()
	go func() { <-ctx.Done(); listener.Close(); client.Close() }()
	url := fmt.Sprintf("http://%s/app/#session=%s", listener.Addr(), session)
	fmt.Fprintf(cmd.OutOrStdout(), "Local Monitor panel: %s\n", url)
	fmt.Fprintln(cmd.ErrOrStderr(), "Keep this command running. Ctrl-C closes the SSH connection. Owner credentials stay out of the browser.")
	if input, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(input.Fd())) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Press Enter to open the Monitor in your browser.")
		// Input must not block forwarding or shutdown of the SSH connection.
		go func() {
			if err := openMonitorBrowserOnEnter(ctx, input, url); err != nil && ctx.Err() == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not open your browser: %v. Open the Local Monitor panel URL above manually.\n", err)
			}
		}()
	}
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
			remote, err := openOwnerChannel(client, dir, listener.Addr().String(), session)
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

func openMonitorBrowserOnEnter(ctx context.Context, input io.Reader, url string) error {
	if ctx.Err() != nil {
		return nil
	}
	if _, err := bufio.NewReader(input).ReadString('\n'); err != nil || ctx.Err() != nil {
		return nil
	}
	return openBrowser(url)
}

var openBrowser = func(url string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.Command(opener, url).Run()
}
