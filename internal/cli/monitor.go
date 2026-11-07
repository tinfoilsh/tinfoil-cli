package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	monitorRepo          = owner.MonitorRepo
	monitorOwnerEnv      = owner.MonitorOwnerEnv
	monitorDeviceKeyName = owner.MonitorDeviceKeyName
	monitorProfileFile   = owner.ProfileFile
)

type accountScope owner.Scope

func (s accountScope) account() string { return owner.Scope(s).Account() }

type monitorProfile = owner.Profile

func newMonitorCommand() *cobra.Command {
	monitorCmd := &cobra.Command{
		Use:   "perimeter",
		Short: "Manage the Perimeter your bunkers connect through",
	}

	return monitorCmd
}

func (a *accountAccess) currentScope(streams commandIO) (accountScope, *cpClient, error) {
	cfg, err := a.requireAuth(streams)
	if err != nil {
		return accountScope{}, nil, err
	}
	identity, err := a.authenticatedContext(streams, cfg)
	if err != nil {
		return accountScope{}, nil, err
	}
	scope := accountScope{ControlplaneURL: cfg.ControlplaneURL, UserID: identity.UserID, UserName: identity.UserName}
	if identity.Organization != nil {
		scope.OrgID, scope.OrgName = identity.Organization.ID, identity.Organization.Name
	}
	if cfg.login != nil && (scope.UserID != cfg.login.UserID || scope.account() != cfg.login.Account) {
		return accountScope{}, nil, errors.New("the API reports a different account than this login; run `tinfoil login` to choose an account")
	}
	return scope, a.client(streams, cfg), nil
}

func updateProfile(dir string, update func(*monitorProfile) error) (monitorProfile, error) {
	return owner.UpdateProfile(dir, update)
}

type monitorSession struct{ *owner.Monitor }

func (m *monitorSession) close() { m.Close() }

func connectMonitorOwner(streams commandIO, identityOpts *identityOptions, rootOpts *rootOptions, ctx context.Context, scope accountScope, cp *cpClient, row *workloadTarget, restoreDevice bool) (*monitorSession, error) {
	service, err := ownerService(streams, identityOpts, cp)
	if err != nil {
		return nil, err
	}
	m, err := service.ConnectMonitor(ctx, owner.Scope(scope), cp.transport(), ownerWorkload(row), restoreDevice, ownerVerifier{streams, rootOpts})
	if err != nil {
		return nil, humanControlplaneError(err)
	}
	return &monitorSession{m}, nil
}

func connectOwnerSigner(conn net.Conn, host string, hostKey ssh.PublicKey, signer ssh.Signer, user string) (*ssh.Client, error) {
	return owner.Connect(conn, host, hostKey, signer, user)
}
func openOwnerChannel(client *ssh.Client, dir, host, token string) (ssh.Channel, error) {
	return owner.OpenChannel(client, dir, host, token)
}

func newMonitorOpenCommand(newScope scopeClientFactory, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions, openBrowser func(string) error) *cobra.Command {
	command := &cobra.Command{
		Use: "open [id|name]", Short: "Unlock and forward the Perimeter UI over attested SSH", Args: cobra.ExactArgs(1),
		Long: "Also restores this device's bunker connectivity.",
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			fmt.Fprintln(cmd.ErrOrStderr(), "Looking up Perimeter "+name)
			scope, cp, err := newScope(commandStreams(cmd))
			if err != nil {
				return err
			}
			row, err := resolveContainerDetail(cp, name)
			if err != nil {
				return err
			}
			target, err := resolveWorkload(commandStreams(cmd), rootOpts, trustOpts, *row, monitorRepo, rootOpts.repo)
			if err != nil {
				return err
			}
			m, err := connectMonitorOwner(commandStreams(cmd), identityOpts, rootOpts, cmd.Context(), scope, cp, target, true)
			if err != nil {
				return err
			}
			defer m.close()
			for _, failure := range relinkSandboxes(commandStreams(cmd), identityOpts, rootOpts, trustOpts, cmd.Context(), scope, cp, m, row.ID) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not re-link %v\n", failure)
			}
			return serveMonitorPanel(cmd, m, "127.0.0.1:0", openBrowser)
		},
	}
	addTrustDangerousFlag(trustOpts, command)
	return command
}

func panelToken() string { return randomB64U(32) }

func serveMonitorPanel(cmd *cobra.Command, monitor *monitorSession, address string, openBrowser func(string) error) error {
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
	fmt.Fprintln(cmd.ErrOrStderr(), "Opening the local Perimeter panel")
	probe, err := monitor.OpenChannel(listener.Addr().String(), session)
	if err != nil {
		return err
	}
	probe.Close()
	url := fmt.Sprintf("http://%s/app/#session=%s", listener.Addr(), session)
	fmt.Fprintf(cmd.OutOrStdout(), "Local Perimeter panel: %s\n", url)
	fmt.Fprintln(cmd.ErrOrStderr(), "Keep this command running. Ctrl-C closes the SSH connection. Owner credentials stay out of the browser.")
	if input, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(input.Fd())) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Press Enter to open the Perimeter in your browser.")
		// Input must not block forwarding or shutdown of the SSH connection.
		go func() {
			if err := openMonitorBrowserOnEnter(ctx, input, url, openBrowser); err != nil && ctx.Err() == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not open your browser: %v. Open the Local Perimeter panel URL above manually.\n", err)
			}
		}()
	}
	return monitor.ForwardPanel(ctx, listener, session)
}

func openMonitorBrowserOnEnter(ctx context.Context, input io.Reader, url string, openBrowser func(string) error) error {
	if ctx.Err() != nil {
		return nil
	}
	if _, err := bufio.NewReader(input).ReadString('\n'); err != nil || ctx.Err() != nil {
		return nil
	}
	return openBrowser(url)
}

func openBrowser(url string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.Command(opener, url).Run()
}
