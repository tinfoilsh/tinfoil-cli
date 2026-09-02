package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const testAPIKey = "test-key"

func echoListener(t *testing.T) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	return address.String(), address.Port
}

func connectServer(t *testing.T, backend string, published int) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testAPIKey {
			http.Error(w, "missing API key", http.StatusUnauthorized)
			return
		}
		if _, port, _ := net.SplitHostPort(r.Host); port != fmt.Sprint(published) {
			http.Error(w, "no container publishes this port", http.StatusNotFound)
			return
		}

		conn, err := net.Dial("tcp", backend)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer conn.Close()

		control := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		if err := control.Flush(); err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(conn, r.Body)
			_ = conn.(*net.TCPConn).CloseWrite()
		}()
		for {
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if n > 0 {
				if _, werr := w.Write(buffer[:n]); werr != nil {
					return
				}
				if ferr := control.Flush(); ferr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func testTunnel(t *testing.T, server *httptest.Server, apiKey string) *tunnel {
	t.Helper()
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, _ string, config *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{Config: config}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &tunnel{transport: transport, host: "enclave.test", apiKey: apiKey}
}

func TestTunnelDialReachesPublishedPort(t *testing.T) {
	backend, port := echoListener(t)
	tun := testTunnel(t, connectServer(t, backend, port), testAPIKey)

	stream, err := tun.dial(port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, 4)
	if _, err := io.ReadFull(stream, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != "ping" {
		t.Fatalf("echoed %q, want \"ping\"", echoed)
	}
}

func TestTunnelDialReportsRefusal(t *testing.T) {
	backend, port := echoListener(t)
	server := connectServer(t, backend, port)

	if _, err := testTunnel(t, server, testAPIKey).dial(port + 1); err == nil ||
		!strings.Contains(err.Error(), "no container publishes this port") {
		t.Errorf("unpublished port error = %v, want the server's explanation", err)
	}
	if _, err := testTunnel(t, server, "").dial(port); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Errorf("keyless dial error = %v, want 401", err)
	}
}

func TestSpliceHalfClosesOnLocalEOF(t *testing.T) {
	backend, port := echoListener(t)
	tun := testTunnel(t, connectServer(t, backend, port), testAPIKey)

	stream, err := tun.dial(port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	local, forwarded := net.Pipe()
	done := make(chan struct{})
	go func() {
		splice(forwarded, stream)
		close(done)
	}()

	if _, err := local.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, 4)
	if _, err := io.ReadFull(local, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != "ping" {
		t.Fatalf("echoed %q, want \"ping\"", echoed)
	}

	local.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("splice did not return after the local side closed")
	}
}

func statusServer(t *testing.T, body string, code int) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if code != http.StatusOK {
			http.Error(w, "container status not available", code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestCheckDebugModeBlocksInjectedToolbox(t *testing.T) {
	previous := allowDebug
	t.Cleanup(func() { allowDebug = previous })

	toolbox := `{"containers":[{"name":"app"},{"name":"` + debugToolboxContainer + `"}]}`
	clean := `{"containers":[{"name":"app"}]}`

	for _, tc := range []struct {
		name        string
		body        string
		code        int
		targetDebug bool
		allow       bool
		wantErr     bool
	}{
		{name: "toolbox blocks", body: toolbox, code: 200, wantErr: true},
		{name: "toolbox allowed with opt-in", body: toolbox, code: 200, allow: true},
		{name: "no toolbox passes", body: clean, code: 200},
		{name: "controlplane debug flag blocks", body: clean, code: 200, targetDebug: true, wantErr: true},
		{name: "unavailable status blocks", body: "", code: 503, wantErr: true},
		{name: "unavailable status allowed with opt-in", body: "", code: 503, allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowDebug = tc.allow
			tun := testTunnel(t, statusServer(t, tc.body, tc.code), testAPIKey)
			err := checkDebugMode(tun, &tunnelTarget{name: "box", host: tun.host, debug: tc.targetDebug})
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkDebugMode = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "--allow-debug") {
				t.Errorf("error does not name the override: %v", err)
			}
		})
	}
}

func TestParseForwardSpec(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want forwardSpec
	}{
		{"25565:25565", forwardSpec{bind: "127.0.0.1", local: 25565, remote: 25565}},
		{"2222:22", forwardSpec{bind: "127.0.0.1", local: 2222, remote: 22}},
		{"0.0.0.0:8080:80", forwardSpec{bind: "0.0.0.0", local: 8080, remote: 80}},
	} {
		got, err := parseForwardSpec(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("parseForwardSpec(%q) = %+v, %v; want %+v", tc.raw, got, err, tc.want)
		}
	}

	for _, raw := range []string{"25565", "a:22", "2222:0", "2222:65536", "1:2:3:4", ":8080:80", ""} {
		if _, err := parseForwardSpec(raw); err == nil {
			t.Errorf("parseForwardSpec(%q) succeeded", raw)
		}
	}
}

func TestSplitSSHArgs(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		wantOptions []string
		wantCommand []string
	}{
		{args: nil},
		{args: []string{"-A", "-L", "5432:localhost:5432"}, wantOptions: []string{"-A", "-L", "5432:localhost:5432"}},
		{args: []string{"systemctl", "status"}, wantCommand: []string{"systemctl", "status"}},
		{args: []string{"-t", "-p2022", "top", "-b"}, wantOptions: []string{"-t", "-p2022"}, wantCommand: []string{"top", "-b"}},
		{args: []string{"-o", "ServerAliveInterval=30", "uptime"}, wantOptions: []string{"-o", "ServerAliveInterval=30"}, wantCommand: []string{"uptime"}},
		{args: []string{"-l", "root", "-J", "jump", "id"}, wantOptions: []string{"-l", "root", "-J", "jump"}, wantCommand: []string{"id"}},
	} {
		options, command := splitSSHArgs(tc.args)
		if !slices.Equal(options, tc.wantOptions) || !slices.Equal(command, tc.wantCommand) {
			t.Errorf("splitSSHArgs(%q) = %q, %q; want %q, %q", tc.args, options, command, tc.wantOptions, tc.wantCommand)
		}
	}
}

func TestProxyCommandNamesResolvedHost(t *testing.T) {
	withRepo, err := proxyCommand(&tunnelTarget{name: "box", host: "box.example.com", repo: "org/repo"}, 22)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(withRepo, "'forward' '--stdio' '22' '--host' 'box.example.com' '--repo' 'org/repo'") {
		t.Errorf("proxy command = %q", withRepo)
	}

	host := "otter-4s7ut6c3.box2.tinfoil.sh"
	bare, err := proxyCommand(&tunnelTarget{name: host, host: host}, 2022)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(bare, "'forward' '--stdio' '2022' '--host' '"+host+"'") {
		t.Errorf("proxy command = %q", bare)
	}
	if strings.Contains(bare, testAPIKey) {
		t.Error("proxy command carries the API key")
	}
}

func TestResolveTunnelTargetTakesHostnamesWithoutControlplane(t *testing.T) {
	previousHost, previousRepo := enclaveHost, repo
	t.Cleanup(func() { enclaveHost, repo = previousHost, previousRepo })
	enclaveHost, repo = "", ""

	host := "courageous-otter-cinders-4s7ut6c3.box2.tinfoil.sh"
	target, err := resolveTunnelTarget(host)
	if err != nil {
		t.Fatalf("resolveTunnelTarget(%q): %v", host, err)
	}
	if target.host != host || target.repo != "" || target.sshPort != 0 {
		t.Errorf("target = %+v", target)
	}

	repo = "org/repo"
	if target, err = resolveTunnelTarget(host); err != nil || target.repo != "org/repo" {
		t.Errorf("--repo not carried onto a hostname target: %+v, %v", target, err)
	}

	repo = ""
	enclaveHost = host
	if target, err = resolveTunnelTarget(""); err != nil || target.host != host {
		t.Errorf("--host not used when no target is named: %+v, %v", target, err)
	}

	enclaveHost = ""
	if _, err = resolveTunnelTarget(""); err == nil {
		t.Error("resolveTunnelTarget with no target and no --host succeeded")
	}
}
