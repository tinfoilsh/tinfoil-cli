package owner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"golang.org/x/crypto/ssh"
)

const (
	ownerSSHChannel        = "tinfoil-owner-http-v1"
	ownerGenerationRequest = "tinfoil-owner-generation-v1"
	ConnectTimeout         = 30 * time.Second
	commandTimeout         = 10 * time.Minute
	maxCommandOutputBytes  = 1 << 12
)

type ownerChannelOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// Authenticate only against the SSH host key endorsed by attestation.
func Connect(conn net.Conn, host string, hostKey ssh.PublicKey, signer ssh.Signer, user string) (*ssh.Client, error) {
	// SSH-forwarded connections do not implement SetDeadline.
	timer := time.AfterFunc(ConnectTimeout, func() { conn.Close() })
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

func OpenChannel(client *ssh.Client, dir, host, token string) (ssh.Channel, error) {
	var profile Profile
	if err := statefile.ReadJSON(filepath.Join(dir, ProfileFile), &profile); err != nil {
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
				_, err := UpdateProfile(dir, func(p *Profile) error {
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

func SendCommand(ctx context.Context, dial func(context.Context) (*ssh.Client, error), command string, body []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	client, err := dial(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(body)
	var output, message limitedCommandOutput
	session.Stdout, session.Stderr = &output, &message
	if err := session.Run(command); err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			return "", fmt.Errorf("owner command has an unknown outcome: %w", err)
		}
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(message)+string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

type limitedCommandOutput []byte

func (b *limitedCommandOutput) Write(p []byte) (int, error) {
	n := min(len(p), maxCommandOutputBytes-len(*b))
	*b = append(*b, p[:n]...)
	return len(p), nil
}
