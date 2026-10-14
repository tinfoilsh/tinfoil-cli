package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestOwnerSSHNegotiatesRSASHA2WithPinnedKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	host, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	host, err = ssh.NewSignerWithAlgorithms(host.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
	require.NoError(t, err)
	address := serveSSHHandshakeTest(t, host)
	for _, pin := range []ssh.PublicKey{host.PublicKey(), testSigner(t).PublicKey()} {
		conn, err := net.Dial("tcp", address)
		require.NoError(t, err)
		client, err := connectOwnerSigner(conn, "monitor.example", pin, testSigner(t), "owner")
		if pin == host.PublicKey() {
			require.NoError(t, err)
			client.Close()
		} else {
			require.ErrorContains(t, err, "host key mismatch")
		}
	}
}

func TestOpenSSHHostKeyAliasUsesBarePinAtNonDefaultPort(t *testing.T) {
	program, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH unavailable")
	}
	host := testSigner(t)
	address := serveSSHHandshakeTest(t, host)
	ip, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)
	require.NotEqual(t, defaultSSHPort, portNumber)
	profile := sshProfile{name: "work.monitor", hostName: ip, port: portNumber, user: monitorSSHUser,
		hostKey: host.PublicKey(), hostKeyAlias: "personal.example"}
	dir := t.TempDir()
	config, pins := filepath.Join(dir, "ssh_config"), filepath.Join(dir, "known_hosts")
	require.NoError(t, os.WriteFile(config, []byte(profile.render()), 0600))
	for _, qualified := range []bool{false, true} {
		pin := profile.pin()
		if qualified {
			pin = knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(profile.hostKeyAlias, port))}, profile.hostKey) + "\n"
		}
		require.NoError(t, os.WriteFile(pins, []byte(pin), 0600))
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		output, err := exec.CommandContext(ctx, program, "-F", config, "-o", "UserKnownHostsFile="+pins,
			"-o", "BatchMode=yes", profile.name, "true").CombinedOutput()
		cancel()
		if qualified {
			require.Error(t, err)
			require.Contains(t, string(output), "Host key verification failed")
		} else {
			require.NoError(t, err, string(output))
		}
	}
}

// Serve real SSH handshakes and a successful exec without owner side effects.
func serveSSHHandshakeTest(t *testing.T, host ssh.Signer) string {
	t.Helper()
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for request := range requests {
						request.Reply(request.Type == "exec", nil)
						if request.Type == "exec" {
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// Invoked by the real Monitor process test after its owner SSH unlock.
func testOwnerSSHPanel(t *testing.T, sshClient *ssh.Client, dir string, seed []byte, hostKey ssh.PublicKey, address string) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	token := panelToken()
	go func() { done <- forwardOwnerPanel(ctx, sshClient, dir, listener, token) }()
	defer func() { cancel(); listener.Close(); require.NoError(t, <-done) }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := "http://" + listener.Addr().String()
	call := func(method, path, body string) (int, string) {
		r, err := http.NewRequest(method, base+path, strings.NewReader(body))
		require.NoError(t, err)
		r.Header.Set("X-Tinfoil-Session", token)
		r.Header.Set("Origin", base)
		res, err := client.Do(r)
		require.NoError(t, err)
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, string(data)
	}
	code, body := call("GET", "/app/", "")
	require.Equal(t, 200, code, body)
	code, body = call("POST", "/api/unlock", `{}`)
	require.Equal(t, 404, code, body)
	code, policy := call("GET", "/api/policy", "")
	require.Equal(t, 200, code)
	require.Contains(t, policy, "source")
	var document struct {
		Source string `json:"source"`
	}
	require.NoError(t, json.Unmarshal([]byte(policy), &document))
	change, err := json.Marshal(map[string]string{"source": document.Source + "\n# SSH forwarding integration test\n"})
	require.NoError(t, err)
	code, reply := call("POST", "/api/policy", string(change))
	require.Equal(t, 200, code, reply)
	// Generation acknowledgments persist even when no CLI code parses the HTTP reply.
	var saved monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &saved))
	require.Positive(t, saved.Generation)
	// Owner authority does not turn into agent forwarding or a shell.
	for _, kind := range []string{"direct-tcpip", "session"} {
		_, _, err := sshClient.OpenChannel(kind, nil)
		require.Error(t, err)
	}
	// Host-key substitution fails before owner authentication or channel opening.
	conn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	_, err = connectOwnerSSH(conn, "localhost", testSigner(t).PublicKey(), seed)
	require.Error(t, err)
	// Unknown SSH keys can publish sandbox routes, but cannot open owner channels.
	stranger, err := newSigningCredential()
	require.NoError(t, err)
	conn, err = net.Dial("tcp", address)
	require.NoError(t, err)
	unowned, err := connectOwnerSSH(conn, "localhost", hostKey, stranger.SigningSeed)
	require.NoError(t, err)
	defer unowned.Close()
	_, err = openOwnerChannel(unowned, dir, "owner.monitor", panelToken())
	require.Error(t, err)
	// Opening a new channel against state older than the client's floor fails.
	_, _, err = sshClient.OpenChannel(ownerSSHChannel, ssh.Marshal(ownerChannelOptions{"owner.monitor", token, saved.Generation + 100}))
	require.Error(t, err)
	// A failed generation save must not produce a successful owner response.
	badDir := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.Mkdir(badDir, 0700))
	require.NoError(t, saveMonitorGeneration(badDir, 0))
	ch, err := openOwnerChannel(sshClient, badDir, "owner.monitor", token)
	require.NoError(t, err)
	defer ch.Close()
	require.NoError(t, os.RemoveAll(badDir))
	require.NoError(t, os.WriteFile(badDir, nil, 0600))
	req, err := http.NewRequest("GET", "http://owner.monitor/api/", nil)
	require.NoError(t, err)
	req.Header.Set("X-Tinfoil-Session", token)
	require.NoError(t, req.Write(ch))
	response, err := http.ReadResponse(bufio.NewReader(ch), req)
	if err == nil {
		defer response.Body.Close()
		require.NotEqual(t, 200, response.StatusCode)
	}
}

func TestSSHGenerationNeverDecreases(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, saveMonitorGeneration(dir, 7))
	require.NoError(t, saveMonitorGeneration(dir, 10))
	require.NoError(t, saveMonitorGeneration(dir, 8))
	errors := make(chan error, 8)
	for generation := uint64(3); generation <= 10; generation++ {
		go func() { errors <- saveMonitorGeneration(dir, generation) }()
	}
	for range 8 {
		require.NoError(t, <-errors)
	}
	var saved monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &saved))
	require.Equal(t, uint64(10), saved.Generation)
}

// Pair through the production owner channel, including generation acknowledgments.
func testSandboxPairing(t *testing.T, client *ssh.Client, dir string, hostKey ssh.PublicKey, address string) (string, string) {
	deviceSigner := testSigner(t)
	device, agent := authorizedLine(deviceSigner), authorizedLine(testSigner(t))
	deviceName := "device-" + storageHash([]byte(device))[:16]
	read := func() map[string]any {
		var view map[string]any
		require.NoError(t, monitorOwnerRequest(client, dir, "GET", "/", nil, &view))
		return view
	}
	identities := func(view map[string]any) map[string]any {
		return view["config"].(map[string]any)["identities"].(map[string]any)
	}
	edit := func(path []string, value any) {
		require.NoError(t, monitorOwnerRequest(client, dir, "POST", "/policy/edits", map[string]any{
			"changes": []map[string]any{{"path": path, "value": value, "delete": value == nil}},
		}, nil))
	}
	require.NoError(t, pairSandboxMonitor(client, dir, "work", device, agent))
	view := read()
	ids := identities(view)
	require.Len(t, ids, 2)
	require.Equal(t, device, ids[deviceName].(map[string]any)["key"])
	require.Equal(t, true, ids[deviceName].(map[string]any)["routes"])
	require.Equal(t, agent, ids["sandbox-work"].(map[string]any)["key"])
	for _, raw := range ids {
		require.Empty(t, raw.(map[string]any)["accounts"], "pairing grants no account access")
	}
	testSandboxRoutes(t, deviceSigner, hostKey, address)
	// A retry does not rewrite identities, including settings it does not model.
	edit([]string{"identities", "sandbox-work", "routes"}, true)
	before := read()
	require.NoError(t, pairSandboxMonitor(client, dir, "work", device, agent))
	require.Equal(t, before, read())
	// Concurrent policy edits reject the entire stale write, rather than losing policy.
	err := monitorOwnerRequest(client, dir, "POST", "/policy/edits", map[string]any{
		"generation": view["generation"],
		"changes":    []map[string]any{{"path": []string{"identities", deviceName, "routes"}, "value": false}},
	}, nil)
	require.ErrorContains(t, err, "409 Conflict")
	require.Equal(t, before, read())
	require.ErrorContains(t, pairSandboxMonitor(client, dir, "work", device, authorizedLine(testSigner(t))), "belongs to another key")
	require.Equal(t, before, read())
	// A paired device can be revoked without creation silently re-enabling it.
	edit([]string{"identities", deviceName, "routes"}, false)
	before = read()
	require.ErrorContains(t, pairSandboxMonitor(client, dir, "work", device, agent), "route access was revoked")
	require.Equal(t, before, read())
	edit([]string{"identities", deviceName, "routes"}, true)
	edit([]string{"identities", "sandbox-work"}, nil)
	require.ErrorContains(t, pairSandboxMonitor(client, dir, "work", device, agent), "identity was revoked")
	return device, agent
}

// Exercise the actual Monitor: a publisher can announce itself before enrollment,
// but only a device with route access can reach it. SSH keeps using the boot key.
func testSandboxRoutes(t *testing.T, device ssh.Signer, hostKey ssh.PublicKey, address string) {
	dial := func(user string, signer ssh.Signer) *ssh.Client {
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
			User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { client.Close() })
		return client
	}
	boot := testSigner(t)
	publisher := dial("sandbox-v2:11111111-1111-4111-8111-111111111111", boot)
	publish := func(client *ssh.Client, port string) net.Listener {
		listener, err := client.Listen("tcp", "127.0.0.1:"+port)
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Write([]byte("sandbox:" + port))
				conn.Close()
			}
		}()
		return listener
	}
	publish(publisher, "443")
	publish(publisher, "22")
	reader := dial("device", device)
	read := func(client *ssh.Client, target string) (string, error) {
		conn, err := client.Dial("tcp", target)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		data, err := io.ReadAll(conn)
		return string(data), err
	}
	for target, want := range map[string]string{
		bootstrapRoute("sandbox-v2:11111111-1111-4111-8111-111111111111") + ":443": "sandbox:443",
		routeName(boot.PublicKey()) + ":443":                                       "sandbox:443",
		routeName(boot.PublicKey()) + ":22":                                        "sandbox:22",
	} {
		got, err := read(reader, target)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	for _, target := range []string{bootstrapRoute("sandbox-v2:11111111-1111-4111-8111-111111111111") + ":22", bootstrapRoute("other.example") + ":443"} {
		_, err := read(reader, target)
		require.Error(t, err)
	}
	// Unknown keys may publish but cannot use a bootstrap name to gain access.
	stranger := dial("device", testSigner(t))
	_, err := read(stranger, bootstrapRoute("sandbox-v2:11111111-1111-4111-8111-111111111111")+":443")
	require.Error(t, err)
	// Two untrusted claims must not silently select a publisher.
	duplicate := dial("sandbox-v2:11111111-1111-4111-8111-111111111111", testSigner(t))
	publish(duplicate, "443")
	_, err = read(reader, bootstrapRoute("sandbox-v2:11111111-1111-4111-8111-111111111111")+":443")
	require.Error(t, err)
	got, err := read(reader, routeName(boot.PublicKey())+":443")
	require.NoError(t, err)
	require.Equal(t, "sandbox:443", got)
}
