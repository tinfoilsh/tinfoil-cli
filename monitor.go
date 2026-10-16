package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	monitorRepo     = "tinfoilsh/confidential-agent-monitor"
	monitorOwnerEnv = "MONITOR_OWNER_PUBLIC_KEY"

	monitorOwnerKeyName  = "owner.key"
	monitorDeviceKeyName = "device_ed25519"
	monitorProfileFile   = "profile.json"

	// Monitor's owner API accepts and returns documents up to this size.
	maxMonitorReplyBytes = 16 << 20

	monitorRequestTimeout = time.Minute

	profileLockAttempts = 50
	profileLockRetry    = 20 * time.Millisecond
)

// Monitor names are scoped to an account and control plane.
type accountScope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id,omitempty"`
	UserID          string `json:"user_id"`
}

// Persist the domain, boot key and minimum generation.
type monitorProfile struct {
	Domain       string `json:"domain"`
	Address      string `json:"address,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	Owner        string `json:"owner_public_key,omitempty"`
	Storage      string `json:"storage,omitempty"`
	HostKey      string `json:"host_key,omitempty"`
	ConfigSource string `json:"config_source,omitempty"`
	Generation   uint64 `json:"generation"`
}

var monitorCmd = &cobra.Command{
	Use:          "monitor",
	Aliases:      []string{"monitors"},
	Short:        "Manage the Monitor your sandboxes connect through",
	SilenceUsage: true,
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
	scope := accountScope{ControlplaneURL: cfg.ControlplaneURL, UserID: identity.UserID}
	if identity.Organization != nil {
		scope.OrgID = identity.Organization.ID
	}
	return scope, newCPClient(cfg), nil
}

// SSH authenticates the owner; the storage key only decrypts the state.
func unlockMonitor(client *ssh.Client, dir string, credential *ownerCredential) error {
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return err
	}
	return monitorOwnerRequest(client, dir, http.MethodPost, "/unlock", struct {
		StorageKey []byte `json:"storage_key"`
		Initialize bool   `json:"initialize"`
	}{credential.Key, profile.Generation == 0})
}

// Serialize updates to preserve boot-key pins and the maximum generation.
func updateProfile(dir string, update func(*monitorProfile) error) (monitorProfile, error) {
	path := filepath.Join(dir, monitorProfileFile)
	unlock, err := acquireStorageLock(path)
	for attempt := 1; err != nil && attempt < profileLockAttempts; attempt++ {
		time.Sleep(profileLockRetry)
		unlock, err = acquireStorageLock(path)
	}
	if err != nil {
		return monitorProfile{}, err
	}
	defer unlock()
	var profile monitorProfile
	if err := readStorageJSON(path, &profile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return profile, err
	}
	if err := update(&profile); err != nil {
		return profile, err
	}
	return profile, writeStorageJSON(path, profile, false)
}

const ownerSSHChannel = "tinfoil-owner-http-v1"
const ownerGenerationRequest = "tinfoil-owner-generation-v1"

type ownerChannelOptions struct {
	Host       string
	Token      string
	Generation uint64
}

func connectMonitorOwner(ctx context.Context, scope accountScope, row *workloadTarget) (*ssh.Client, string, error) {
	if err := requireRunningConnection("Monitor", row.containerView); err != nil {
		return nil, "", err
	}
	if row.SSHPort < 1 || row.SSHPort > maxConnectionPort {
		return nil, "", errors.New("Monitor has no published SSH port")
	}
	fmt.Fprintf(os.Stderr, "Monitor %s: running.\n", row.Name)
	dir, err := monitorRecord(scope, row)
	if err != nil {
		return nil, "", err
	}
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return nil, "", err
	}
	credential, err := resourceCredential(dir, monitorOwnerKeyName, row.env[monitorOwnerEnv], profile.Generation != 0)
	if err != nil {
		return nil, "", err
	}
	defer credential.clear()
	if profile.Generation == 0 {
		if _, err := ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName)); err != nil {
			return nil, "", err
		}
	}
	if row.Domain != profile.Domain {
		return nil, "", errors.New("Monitor no longer matches its saved domain")
	}
	hostKey, err := attestedHostKey(row.Domain, row.source, "")
	if err != nil {
		return nil, "", err
	}
	attested := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	if profile.HostKey != attested || profile.ConfigSource != row.source {
		if _, err := updateProfile(dir, func(p *monitorProfile) error {
			if p.HostKey != profile.HostKey || p.ConfigSource != profile.ConfigSource {
				return errors.New("another command changed the pinned Monitor SSH host key; run this again")
			}
			p.HostKey = attested
			p.ConfigSource = row.source
			return nil
		}); err != nil {
			return nil, "", err
		}
	}
	fmt.Fprintf(os.Stderr, "Monitor %s attestation verified.\n", row.Name)
	signer, _, close, err := ownerSigner(credential, dir)
	if err != nil {
		return nil, "", err
	}
	defer close()
	fmt.Fprintln(os.Stderr, "Connecting to Monitor "+row.Name+" over attested SSH")
	address := net.JoinHostPort(row.Domain, strconv.Itoa(row.SSHPort))
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", err
	}
	client, err := connectOwnerSigner(conn, row.Domain, hostKey, signer, "owner")
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintln(os.Stderr, "Unlocking Monitor "+row.Name+" encrypted state")
	err = unlockMonitor(client, dir, credential)
	if err != nil {
		client.Close()
		return nil, "", fmt.Errorf("unlock Monitor; restore the original encryption credentials if it was initialized elsewhere: %w", err)
	}
	if _, err := updateProfile(dir, func(p *monitorProfile) error { p.Address = address; return nil }); err != nil {
		client.Close()
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, "Monitor %s unlocked.\n", row.Name)
	return client, dir, nil
}

func monitorRecord(scope accountScope, row *workloadTarget) (string, error) {
	dir, err := credentialDir(scope, row.containerView)
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
func monitorOwnerRequest(client *ssh.Client, dir, method, path string, input any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	defer clear(data)
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
	req.Header.Set("Content-Type", "application/json")
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
	return nil
}

// Authenticate only against the SSH host key endorsed by attestation.
func connectOwnerSigner(conn net.Conn, host string, hostKey ssh.PublicKey, signer ssh.Signer, user string) (*ssh.Client, error) {
	// SSH-forwarded connections do not implement SetDeadline.
	timer := time.AfterFunc(30*time.Second, func() { conn.Close() })
	defer timer.Stop()
	c, channels, requests, err := ssh.NewClientConn(conn, host, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("owner SSH: %w", err)
	}
	return ssh.NewClient(c, channels, requests), nil
}

func openOwnerChannel(client *ssh.Client, dir, host, token string) (ssh.Channel, error) {
	var profile monitorProfile
	if err := readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile); err != nil {
		return nil, err
	}
	ch, requests, err := client.OpenChannel(ownerSSHChannel, ssh.Marshal(ownerChannelOptions{host, token, profile.Generation}))
	if err != nil {
		return nil, err
	}
	go func() {
		for request := range requests {
			var message struct{ Generation uint64 }
			ok := request.Type == ownerGenerationRequest && request.WantReply && ssh.Unmarshal(request.Payload, &message) == nil && message.Generation >= profile.Generation
			if ok {
				_, err := updateProfile(dir, func(p *monitorProfile) error {
					p.Generation = max(p.Generation, message.Generation)
					return nil
				})
				ok = err == nil
			}
			request.Reply(ok, nil)
			if !ok {
				ch.Close()
				return
			}
		}
	}()
	return ch, nil
}

// Monitor commits enrollment once and remembers revoked keys across retries.
func pairSandboxMonitor(client *ssh.Client, dir, name, device, agent string) error {
	return monitorOwnerRequest(client, dir, "POST", "/enroll", map[string]any{
		"device-" + storageHash([]byte(device))[:16]: map[string]any{"key": device, "routes": true},
		"sandbox-" + name: map[string]any{"key": agent},
	})
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	command := &cobra.Command{
		Use: "open [id|name]", Short: "Unlock and forward the Monitor UI over attested SSH", Args: cobra.ExactArgs(1),
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
			target, err := resolveWorkload(*row, monitorRepo, repo)
			if err != nil {
				return err
			}
			client, dir, err := connectMonitorOwner(cmd.Context(), scope, target)
			if err != nil {
				return err
			}
			defer client.Close()
			return serveMonitorPanel(cmd, client, dir, "127.0.0.1:0")
		},
	}
	addTrustDangerousFlag(command)
	monitorCmd.AddCommand(command)
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
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.CommandContext(ctx, opener, url).Run()
}
