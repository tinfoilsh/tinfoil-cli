package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type fakeSandboxOwner struct {
	key      *ecdh.PrivateKey
	owner    ed25519.PublicKey
	reply    func(ownerCall) any
	mode     string
	hits     atomic.Int64
	mu       sync.Mutex
	requests []ownerCall
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

func (f *fakeSandboxOwner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if r.Method != http.MethodGet || r.URL.Path != "/owner/ws" {
		http.NotFound(w, r)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	hs, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:     noise.HandshakeNK, Prologue: []byte("sandbox-owner-v1"),
		StaticKeypair: noise.DHKey{Private: f.key.Bytes(), Public: f.key.PublicKey().Bytes()},
	})
	_, message, err := conn.Read(ctx)
	if err != nil {
		return
	}
	if _, _, _, err = hs.ReadMessage(nil, message); err != nil {
		return
	}
	message, recv, send, err := hs.WriteMessage(nil, nil)
	if err != nil || conn.Write(ctx, websocket.MessageBinary, message) != nil {
		return
	}
	read := func(out any) error {
		_, frame, err := conn.Read(ctx)
		if err == nil {
			frame, err = recv.Decrypt(nil, nil, frame)
		}
		if err != nil || len(frame) == 0 || frame[0] != 1 {
			return errors.New("invalid owner frame")
		}
		return json.Unmarshal(frame[1:], out)
	}
	var hello struct {
		Signature []byte `json:"signature"`
		Open      string `json:"open"`
	}
	if read(&hello) != nil || hello.Open != "rpc" || !ed25519.Verify(f.owner, append([]byte("tinfoil owner session v1\x00"), hs.ChannelBinding()...), hello.Signature) {
		conn.Close(websocket.StatusPolicyViolation, "invalid_signature")
		return
	}
	var call ownerCall
	if read(&call) != nil {
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, call)
	body, _ := json.Marshal(f.reply(call))
	f.mu.Unlock()
	if f.mode == "lost reply" {
		return
	}
	reply := ownerReply{ID: call.ID, Status: http.StatusOK, Body: body}
	if f.mode == "wrong call" {
		reply.ID++
	}
	if f.mode == "refused" {
		reply.Status = http.StatusConflict
	}
	message, _ = json.Marshal(reply)
	for {
		n := min(len(message), ownerFrameBytes)
		flag := byte(ownerFrameMore)
		if n == len(message) {
			flag = ownerFrameLast
		}
		frame := append([]byte{flag}, message[:n]...)
		if f.mode == "invalid flag" {
			frame[0] = 2
		}
		sealed, _ := send.Encrypt(nil, nil, frame)
		if f.mode == "tampered" {
			sealed[0] ^= 1
		}
		kind := websocket.MessageBinary
		if f.mode == "text frame" {
			kind = websocket.MessageText
		}
		if conn.Write(ctx, kind, sealed) != nil || flag == ownerFrameLast {
			return
		}
		message = message[n:]
	}
}

func testSandboxOwner(t *testing.T, seed []byte, reply func(ownerCall) any) (*sandboxOwner, *fakeSandboxOwner) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	endpoint := &fakeSandboxOwner{key: key, owner: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), reply: reply}
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &sandboxOwner{key: key.PublicKey(), signer: signer, expires: time.Now().Add(time.Hour), client: &http.Client{Transport: transport}}, endpoint
}

func TestSandboxOwnerSession(t *testing.T) {
	for _, mode := range []string{"valid", "fragmented", "wrong key", "wrong owner", "expired", "canceled", "lost reply", "tampered", "invalid flag", "text frame", "wrong call", "oversized", "refused"} {
		t.Run(mode, func(t *testing.T) {
			body := "unlocked"
			if mode == "fragmented" {
				body = strings.Repeat("ok", ownerFrameBytes)
			}
			if mode == "oversized" {
				body = strings.Repeat("x", maxOwnerReplyBytes)
			}
			owner, endpoint := testSandboxOwner(t, testSeed(t), func(call ownerCall) any {
				require.Equal(t, "/enroll", call.Path)
				require.JSONEq(t, `{"disk_key":"secret"}`, string(call.Body))
				return body
			})
			endpoint.mode = mode
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "wrong key":
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				require.NoError(t, err)
				owner.key = key.PublicKey()
			case "wrong owner":
				owner.signer = testSigner(t)
			case "expired":
				owner.expires = time.Now().Add(-time.Second)
			case "canceled":
				cancel()
			}
			var result string
			err := owner.call(ctx, http.MethodPost, "/enroll", map[string]string{"disk_key": "secret"}, &result)
			if mode == "valid" || mode == "fragmented" {
				require.NoError(t, err)
				require.Equal(t, body, result)
			} else {
				require.Error(t, err)
			}
			if mode == "wrong key" || mode == "wrong owner" || mode == "expired" || mode == "canceled" {
				require.Empty(t, endpoint.calls(), "unauthenticated calls never reach the owner API")
			} else {
				require.Len(t, endpoint.calls(), 1, "lost or malformed replies never repeat an effect")
			}
			if mode == "expired" || mode == "canceled" {
				require.Zero(t, endpoint.hits.Load())
			}
			if mode == "lost reply" {
				require.ErrorContains(t, err, "unknown outcome")
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
					if next.ChannelType() != "direct-tcpip" || ssh.Unmarshal(next.ExtraData(), &target) != nil || target.Port != 443 {
						next.Reject(ssh.Prohibited, "invalid route")
						continue
					}
					address := routes[net.JoinHostPort(target.Host, sandboxOwnerPort)]
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
