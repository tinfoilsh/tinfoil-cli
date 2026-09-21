package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExpectedReleaseIsResolvedIndependentlyAndPinned(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/repos/org/workload/releases/latest":
			w.Write([]byte(`{"tag_name":"v1"}`))
		case "/org/workload/releases/download/v1/tinfoil.hash":
			w.Write([]byte(digest + "\n"))
		default:
			t.Errorf("unexpected release request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := resolveRepository(server.Client(), server.URL, "org/workload")
	if err != nil || got != "org/workload@v1@sha256:"+digest || calls != 2 {
		t.Fatalf("expected release = %q, %v (%d calls)", got, err, calls)
	}
	for _, pin := range []string{"org/workload@approved", "org/workload@sha256:" + digest, got} {
		resolved, err := resolveRepository(server.Client(), server.URL, pin)
		if err != nil || resolved != pin || calls != 2 {
			t.Fatalf("explicit pin changed or caused lookup: %q %v", resolved, err)
		}
	}
}

func TestReleaseLookupFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, tag, digest string
		status            int
	}{
		{"lookup unavailable", `{"tag_name":"v1"}`, strings.Repeat("a", 64), 503},
		{"empty tag", `{}`, strings.Repeat("a", 64), 200},
		{"selector injection", `{"tag_name":"v1@sha256:bad"}`, strings.Repeat("a", 64), 200},
		{"malformed digest", `{"tag_name":"v1"}`, "bad", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				if strings.HasSuffix(r.URL.Path, "/latest") {
					w.Write([]byte(test.tag))
				} else {
					w.Write([]byte(test.digest))
				}
			}))
			defer server.Close()
			if _, err := resolveRepository(server.Client(), server.URL, "org/workload"); err == nil {
				t.Fatal("invalid expected release accepted")
			}
		})
	}
}
