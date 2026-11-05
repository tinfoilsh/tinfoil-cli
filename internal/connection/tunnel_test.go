package connection

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
		if r.ProtoMajor != 2 {
			http.Error(w, "expected HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
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

func testTunnel(t *testing.T, server *httptest.Server, apiKey string) *Tunnel {
	t.Helper()
	transport := server.Client().Transport
	t.Cleanup(server.Client().CloseIdleConnections)
	return &Tunnel{transport: transport, host: strings.TrimPrefix(server.URL, "https://"), apiKey: apiKey}
}

func TestTunnelDialReachesPublishedPort(t *testing.T) {
	backend, port := echoListener(t)
	tun := testTunnel(t, connectServer(t, backend, port), testAPIKey)

	stream, err := tun.Dial(port)
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

	if _, err := testTunnel(t, server, testAPIKey).Dial(port + 1); err == nil ||
		!strings.Contains(err.Error(), "no container publishes this port") {
		t.Errorf("unpublished port error = %v, want the server's explanation", err)
	}
	if _, err := testTunnel(t, server, "").Dial(port); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Errorf("keyless dial error = %v, want 401", err)
	}
}

func TestSpliceHalfClosesOnLocalEOF(t *testing.T) {
	backend, port := echoListener(t)
	tun := testTunnel(t, connectServer(t, backend, port), testAPIKey)

	stream, err := tun.Dial(port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	local, forwarded := net.Pipe()
	done := make(chan struct{})
	go func() {
		Splice(forwarded, stream)
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
			tun := testTunnel(t, statusServer(t, tc.body, tc.code), testAPIKey)
			err := checkDebugMode(tun, tc.targetDebug, tc.allow)
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
		want ForwardSpec
	}{
		{"25565:25565", ForwardSpec{Bind: "127.0.0.1", Local: 25565, Remote: 25565}},
		{"2222:22", ForwardSpec{Bind: "127.0.0.1", Local: 2222, Remote: 22}},
		{"0.0.0.0:8080:80", ForwardSpec{Bind: "0.0.0.0", Local: 8080, Remote: 80}},
	} {
		got, err := ParseForwardSpec(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("parseForwardSpec(%q) = %+v, %v; want %+v", tc.raw, got, err, tc.want)
		}
	}

	for _, raw := range []string{"25565", "a:22", "2222:0", "2222:65536", "1:2:3:4", ":8080:80", ""} {
		if _, err := ParseForwardSpec(raw); err == nil {
			t.Errorf("parseForwardSpec(%q) succeeded", raw)
		}
	}
}
