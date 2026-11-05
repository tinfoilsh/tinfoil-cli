package owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type ownerCall struct {
	Method, Path string
	Body         []byte
}

type fakeSandboxOwner struct {
	owner     ed25519.PublicKey
	reply     func(ownerCall) any
	session   *sandboxSession
	loseReply bool
	hits      atomic.Int64
	mu        sync.Mutex
	requests  []ownerCall
}

func (f *fakeSandboxOwner) calls() []ownerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeSandboxOwner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

func (f *fakeSandboxOwner) call(command string, body []byte) ([]byte, error) {
	call := ownerCall{Body: body}
	switch command {
	case sandboxStatusCommand:
		call.Method, call.Path = http.MethodGet, "/status"
	case sandboxEnrollCommand:
		call.Method, call.Path = http.MethodPost, "/enroll"
	default:
		return nil, errors.New("unexpected owner command")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, call)
	reply := f.reply(call)
	if err, ok := reply.(error); ok {
		return nil, err
	}
	return json.Marshal(reply)
}

func testSandboxSSH(t *testing.T, host ssh.Signer, owner *fakeSandboxOwner) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	public, err := ssh.NewPublicKey(owner.owner)
	require.NoError(t, err)
	config := &ssh.ServerConfig{PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if conn.User() != sandboxLoginUser || !bytes.Equal(key.Marshal(), public.Marshal()) {
			return nil, errors.New("wrong owner")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			owner.hits.Add(1)
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				next, ok := <-channels
				if !ok {
					return
				}
				if next.ChannelType() != "session" {
					next.Reject(ssh.Prohibited, "only owner commands")
					return
				}
				channel, pending, err := next.Accept()
				if err != nil {
					return
				}
				defer channel.Close()
				request, ok := <-pending
				if !ok {
					return
				}
				var command struct{ Command string }
				if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
					request.Reply(false, nil)
					return
				}
				request.Reply(true, nil)
				body, err := io.ReadAll(channel)
				if err != nil {
					return
				}
				reply, err := owner.call(command.Command, body)
				if owner.loseReply {
					return
				}
				var code uint32
				if err != nil {
					code = 1
					io.WriteString(channel.Stderr(), err.Error())
				} else {
					channel.Write(reply)
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			}()
		}
	}()
	return listener.Addr().String()
}

func testSandboxOwner(t *testing.T, seed []byte, reply func(ownerCall) any) (*sandboxOwner, *fakeSandboxOwner) {
	t.Helper()
	host := testSigner(t)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	endpoint := &fakeSandboxOwner{owner: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), reply: reply}
	address := testSandboxSSH(t, host, endpoint)
	hostname, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)
	endpoint.session = &sandboxSession{box: containerView{Domain: "sandbox.example"}, keys: &resourceKeys{signer: signer},
		expires: time.Now().Add(time.Hour), profile: ConnectionInfo{HostName: hostname, Port: portNumber, HostKey: host.PublicKey()}}
	return &sandboxOwner{dial: endpoint.session.dial, expires: endpoint.session.expires}, endpoint
}

func TestSandboxOwnerSSH(t *testing.T) {
	for _, mode := range []string{"valid", "wrong host", "wrong owner", "expired", "canceled", "lost reply", "refused"} {
		t.Run(mode, func(t *testing.T) {
			owner, endpoint := testSandboxOwner(t, testSeed(t), func(ownerCall) any {
				if mode == "refused" {
					return errors.New("owner refused")
				}
				return "unlocked"
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "wrong host":
				endpoint.session.profile.HostKey = testSigner(t).PublicKey()
			case "wrong owner":
				endpoint.session.keys.signer = testSigner(t)
			case "expired":
				owner.expires = time.Now().Add(-time.Second)
			case "canceled":
				cancel()
			case "lost reply":
				endpoint.loseReply = true
			}
			var result string
			err := owner.call(ctx, sandboxEnrollCommand, map[string]string{"disk_key": "secret"}, &result)
			if mode == "valid" {
				require.NoError(t, err)
				require.Equal(t, "unlocked", result)
			} else {
				require.Error(t, err)
			}
			calls := endpoint.calls()
			if mode == "valid" || mode == "lost reply" || mode == "refused" {
				require.Len(t, calls, 1, "a dropped reply never repeats an enrollment")
				require.Equal(t, "/enroll", calls[0].Path)
				require.JSONEq(t, `{"disk_key":"secret"}`, string(calls[0].Body))
			} else {
				require.Empty(t, calls, "unverified peers never receive owner credentials")
			}
			if mode == "expired" || mode == "canceled" {
				require.Zero(t, endpoint.hits.Load())
			}
			if mode == "lost reply" {
				require.ErrorContains(t, err, "unknown outcome")
			}
			if mode == "refused" {
				require.ErrorContains(t, err, "owner refused")
				require.NotContains(t, err.Error(), "unknown outcome")
			}
		})
	}
}
func testSandboxRoutes(t *testing.T, host ssh.Signer, device ssh.PublicKey, routes map[string]string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	config := &ssh.ServerConfig{PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if conn.User() != monitorSSHUser || !bytes.Equal(key.Marshal(), device.Marshal()) {
			return nil, errors.New("unexpected device")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					var target struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if next.ChannelType() != "direct-tcpip" || ssh.Unmarshal(next.ExtraData(), &target) != nil || target.Port != uint32(defaultSSHPort) {
						next.Reject(ssh.Prohibited, "invalid route")
						continue
					}
					address := routes[net.JoinHostPort(target.Host, strconv.Itoa(defaultSSHPort))]
					if address == "" {
						next.Reject(ssh.Prohibited, "unknown route")
						continue
					}
					upstream, err := net.Dial("tcp", address)
					if err != nil {
						next.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					channel, reqs, err := next.Accept()
					if err != nil {
						upstream.Close()
						continue
					}
					go ssh.DiscardRequests(reqs)
					go func() {
						io.Copy(channel, upstream)
						channel.Close()
						upstream.Close()
					}()
					go func() { io.Copy(upstream, channel); upstream.Close() }()
				}
			}()
		}
	}()
	return listener.Addr().String()
}
