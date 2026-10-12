package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func init() {
	command := &cobra.Command{
		Use: "open NAME", Short: "Forward the Monitor UI over attested SSH", Args: cobra.ExactArgs(1),
		Long: "Unlock and forward the Monitor UI over attested SSH.",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := sandboxName(args[0])
			if err != nil {
				return err
			}
			scope, cp, err := currentScope()
			if err != nil {
				return err
			}
			row, err := containerNamed(cp, name)
			if err != nil {
				return err
			}
			client, dir, err := connectMonitorOwner(cmd.Context(), scope, row)
			if err != nil {
				return err
			}
			defer client.Close()
			return serveMonitorPanel(cmd, client, dir, "127.0.0.1:0")
		},
	}
	command.Flags().StringVar(&attestSSHIdentity, "identity", "", "Owner SSH identity file")
	monitorCmd.AddCommand(command)
}

func panelToken() string {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}
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
	probe, err := openOwnerChannel(client, dir, listener.Addr().String(), session)
	if err != nil {
		return err
	}
	probe.Close()
	go func() { client.Wait(); stop() }()
	go func() { <-ctx.Done(); listener.Close(); client.Close() }()
	fmt.Fprintf(cmd.OutOrStdout(), "Local Monitor panel: http://%s/app/#session=%s\n", listener.Addr(), session)
	fmt.Fprintln(cmd.ErrOrStderr(), "Keep this command running. Ctrl-C closes the SSH connection. Owner credentials stay out of the browser.")
	return forwardOwnerPanel(ctx, client, dir, listener, session)
}

// No HTTP parsing or signing here. CAM serves both assets and API on this stream.
func forwardOwnerPanel(ctx context.Context, client *ssh.Client, dir string, listener net.Listener, token string) error {
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
			remote, err := openOwnerChannel(client, dir, listener.Addr().String(), token)
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
