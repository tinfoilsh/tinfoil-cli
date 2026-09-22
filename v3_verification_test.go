package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func TestOwnerPinAddsNativeTDXRTMR3(t *testing.T) {
	options, err := verificationOptions("")
	if err != nil || options != nil {
		t.Fatalf("unsealed policy = %+v, %v", options, err)
	}
	seal := strings.Repeat("AB", 48)
	options, err = verificationOptions(seal)
	if err != nil {
		t.Fatal(err)
	}
	pin := options.PinnedRegisters
	if pin.Type != measurement.TdxGuestV2 || len(pin.Registers) != 5 || pin.Registers[4] != strings.ToLower(seal) {
		t.Fatalf("incorrect native RTMR3 pin: %+v", pin)
	}
	for _, value := range pin.Registers[:4] {
		if value != "" {
			t.Fatal("owner pin replaced another register policy")
		}
	}
	for _, invalid := range []string{"abc", strings.Repeat("0", 94), strings.Repeat("g", 96)} {
		if _, err := verificationOptions(invalid); err == nil {
			t.Errorf("invalid seal %q accepted", invalid)
		}
	}
}

func TestV3RejectsMissingExpectedRepositoryBeforeDial(t *testing.T) {
	if _, err := newVerifiedClient("unreachable.invalid", "", ""); err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("missing repository = %v", err)
	}
	if _, err := newTunnel(&tunnelTarget{host: "unreachable.invalid"}); err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("hostname-only tunnel = %v", err)
	}
	selector := "org/workload@v1@sha256:" + strings.Repeat("a", 64)
	sc, err := newVerifiedClient("unreachable.invalid", selector, "")
	if err != nil || sc.Repo() != selector {
		t.Fatalf("release selector was not preserved: %v", err)
	}
}

func TestProxyRequiresHostAndRepositoryTogether(t *testing.T) {
	previousHost, previousRepo := enclaveHost, repo
	t.Cleanup(func() { enclaveHost, repo = previousHost, previousRepo })
	for _, target := range [][2]string{{"unreachable.invalid", ""}, {"", "org/workload"}} {
		enclaveHost, repo = target[0], target[1]
		if err := proxyCmd.RunE(proxyCmd, nil); err == nil || !strings.Contains(err.Error(), "--repo") {
			t.Fatalf("incomplete proxy policy did not fail before dial: %v", err)
		}
	}
}

func TestTunnelPinBeforeSendingCredentials(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing test credential")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	fingerprint, err := client.ConnectionCertFP(tls.ConnectionState{PeerCertificates: []*x509.Certificate{server.Certificate()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{false, true} {
		pin := strings.Repeat("0", 64)
		if valid {
			pin = fingerprint
		}
		transport := newPinnedTunnelTransport(server.Listener.Addr().String(), pin)
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
		transport.TLSClientConfig.RootCAs.AddCert(server.Certificate())
		// The request authority's guest port is intentionally not the server
		// listener. The transport must still dial the attestation endpoint.
		req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:22/status", nil)
		req.Header.Set("Authorization", "Bearer secret")
		response, err := transport.RoundTrip(req)
		if valid {
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if requests.Load() != 1 {
				t.Fatal("correctly pinned request did not reach the server")
			}
		} else if !errors.Is(err, errTunnelCertMismatch) || requests.Load() != 0 {
			t.Fatalf("wrong pin: requests=%d error=%v", requests.Load(), err)
		}
		transport.CloseIdleConnections()
	}
}
