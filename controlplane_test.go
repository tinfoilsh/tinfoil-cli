package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPathfEscapesSegments(t *testing.T) {
	tests := []struct {
		name   string
		format string
		segs   []string
		want   string
	}{
		{
			name:   "plain segment",
			format: "/api/secrets/%s",
			segs:   []string{"DATABASE_URL"},
			want:   "/api/secrets/DATABASE_URL",
		},
		{
			name:   "hyphenated kebab name",
			format: "/api/ssh-keys/%s",
			segs:   []string{"my-deploy-key"},
			want:   "/api/ssh-keys/my-deploy-key",
		},
		{
			name:   "uuid is unchanged",
			format: "/api/containers/%s/deploy",
			segs:   []string{"61bd4a3e-5b48-4320-9215-0c7a7f974979"},
			want:   "/api/containers/61bd4a3e-5b48-4320-9215-0c7a7f974979/deploy",
		},
		{
			name:   "slash in name does not split segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo/bar"},
			want:   "/api/secrets/foo%2Fbar",
		},
		{
			name:   "traversal cannot reach a sibling endpoint",
			format: "/api/ssh-keys/%s",
			segs:   []string{"../secrets/X"},
			want:   "/api/ssh-keys/..%2Fsecrets%2FX",
		},
		{
			name:   "query separator stays in segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo?delete=true"},
			want:   "/api/secrets/foo%3Fdelete=true",
		},
		{
			name:   "fragment separator stays in segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo#bar"},
			want:   "/api/secrets/foo%23bar",
		},
		{
			name:   "space encoded",
			format: "/api/secrets/%s",
			segs:   []string{"foo bar"},
			want:   "/api/secrets/foo%20bar",
		},
		{
			name:   "multiple segments",
			format: "/api/orgs/%s/keys/%s",
			segs:   []string{"acme/admin", "k1"},
			want:   "/api/orgs/acme%2Fadmin/keys/k1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathf(tt.format, tt.segs...)
			if got != tt.want {
				t.Fatalf("pathf(%q, %v) = %q, want %q", tt.format, tt.segs, got, tt.want)
			}
		})
	}
}

func TestControlplaneRequestsSendVersionedUserAgent(t *testing.T) {
	setVersionForTest(t, "0.16.0")

	userAgent := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent <- r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client := &cpClient{baseURL: server.URL, http: server.Client()}
	if _, err := client.do(http.MethodGet, "/test", nil, nil, nil); err != nil {
		t.Fatalf("request: %v", err)
	}
	if got := <-userAgent; got != "tinfoil-cli/0.16.0" {
		t.Fatalf("User-Agent = %q, want %q", got, "tinfoil-cli/0.16.0")
	}
}

func TestControlplaneErrorsKeepMessageAndHintAtLimits(t *testing.T) {
	const message = "Your organization is using 5 of the 5 sandboxes allowed on Tier 1."
	for _, tt := range []struct {
		code     string
		status   int
		wantHint string
	}{
		{code: containerLimitReached, status: http.StatusConflict, wantHint: accountLimitsHint},
		{code: sandboxLimitReached, status: http.StatusConflict, wantHint: accountLimitsHint},
		{code: storageLimitExceeded, status: http.StatusConflict, wantHint: accountLimitsHint},
		{code: "INSUFFICIENT_CREDITS", status: http.StatusPaymentRequired},
		{status: http.StatusConflict},
	} {
		t.Run(tt.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, `{"error":"`+message+`","code":"`+tt.code+`","limit":5,"in_use":5,"tier":1}`)
			}))
			defer server.Close()

			client := &cpClient{baseURL: server.URL, http: server.Client()}
			_, err := client.do(http.MethodPost, "/api/containers", nil, map[string]any{}, nil)
			err = fmt.Errorf("%w; inspect `tinfoil sandbox status` before retrying creation", err)
			if !strings.Contains(err.Error(), message) {
				t.Fatalf("error = %v, want the server's message %q", err, message)
			}
			if got := errorHint(err); got != tt.wantHint {
				t.Fatalf("errorHint = %q, want %q", got, tt.wantHint)
			}
		})
	}
}

func TestVersionFlagUsesInjectedVersion(t *testing.T) {
	setVersionForTest(t, "0.16.0")

	cmd := newRootCommand()
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute --version: %v", err)
	}
	if got := output.String(); got != "tinfoil version 0.16.0\n" {
		t.Fatalf("output = %q, want %q", got, "tinfoil version 0.16.0\n")
	}
}

func setVersionForTest(t *testing.T, value string) {
	t.Helper()
	previousVersion := version
	version = value
	t.Cleanup(func() {
		version = previousVersion
	})
}
