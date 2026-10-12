package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const ownerSSHChannel = "tinfoil-owner-http-v1"
const ownerGenerationRequest = "tinfoil-owner-generation-v1"

type ownerChannelOptions struct {
	Host       string
	Token      string
	Generation uint64
}

func connectMonitorOwner(ctx context.Context, scope accountScope, row containerView, repin bool) (*ssh.Client, string, error) {
	_, hostKey, err := verifyMonitor(scope, row, repin)
	if err != nil {
		return nil, "", err
	}
	dir, err := monitorDir(scope, row.Name)
	if err != nil {
		return nil, "", err
	}
	credential, err := readOwnerCredential(filepath.Join(dir, monitorOwnerKeyName))
	if err != nil {
		return nil, "", err
	}
	defer credential.clear()
	address, err := monitorAddress(ctx, row)
	if err != nil {
		return nil, "", err
	}
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", err
	}
	client, err := connectOwnerSSH(conn, row.Domain, hostKey, credential.SigningSeed)
	if err != nil {
		return nil, "", err
	}
	if err := unlockMonitor(client, dir, credential); err != nil {
		client.Close()
		return nil, "", err
	}
	return client, dir, nil
}

// The public SSH endpoint is shared by owner UI access and device routes.
func monitorAddress(ctx context.Context, row containerView) (string, error) {
	if row.SSHPort < 1 || row.SSHPort > maxConnectionPort {
		return "", errors.New("Monitor has no published SSH port")
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", row.Domain)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("Monitor domain has no IPv4 address")
	}
	return net.JoinHostPort(addresses[0].String(), strconv.Itoa(row.SSHPort)), nil
}

// Owner API calls use the UI's attested channel and persist its generation acknowledgments.
func monitorOwnerRequest(client *ssh.Client, dir, method, path string, input, output any) error {
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
	if output != nil {
		decoder := json.NewDecoder(bytes.NewReader(reply))
		decoder.UseNumber()
		return decoder.Decode(output)
	}
	return nil
}

// Authenticate only against the SSH host key endorsed by attestation.
func connectOwnerSSH(conn net.Conn, host string, hostKey ssh.PublicKey, seed []byte) (*ssh.Client, error) {
	return connectOwnerSSHAs(conn, host, hostKey, seed, "owner")
}

func connectOwnerSSHAs(conn net.Conn, host string, hostKey ssh.PublicKey, seed []byte, user string) (*ssh.Client, error) {
	if hostKey == nil || len(seed) != ed25519.SeedSize {
		conn.Close()
		return nil, errors.New("owner SSH requires the attested host key and owner signing key")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		conn.Close()
		return nil, err
	}
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
				ok = saveMonitorGeneration(dir, message.Generation) == nil
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

func saveMonitorGeneration(dir string, generation uint64) error {
	// The file lock also serializes other commands and channels. Replies can
	// arrive out of order, so only advance the saved rollback counter.
	_, err := updateProfile(dir, func(p *monitorProfile) error {
		p.Generation = max(p.Generation, generation)
		return nil
	})
	return err
}
