package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestNativeOpenSSHHostKeyAliasOnAssignedPort(t *testing.T) {
	binary, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	signer := testSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for request := range channels {
			channel, requests, err := request.Accept()
			if err != nil {
				return
			}
			for r := range requests {
				if r.Type == "exec" {
					r.Reply(true, nil)
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()
					return
				}
				r.Reply(false, nil)
			}
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	profile := sshProfile{hostName: "127.0.0.1", port: port, hostKeyAlias: "monitor-alias", hostKey: signer.PublicKey()}
	known := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(known, []byte(profile.pin()), 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-F", "/dev/null", "-o", "HostKeyAlias=monitor-alias", "-o", "UserKnownHostsFile="+known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none", "-p", strconv.Itoa(port), "127.0.0.1", "true")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}
