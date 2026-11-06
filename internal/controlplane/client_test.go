package controlplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenSourceFunc func(context.Context) (string, error)

func (f tokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

func TestRequestPreservesContextHeadersAndEncoding(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request")
	tokens := tokenSourceFunc(func(got context.Context) (string, error) {
		require.Same(t, ctx, got)
		return "admin_test", nil
	})
	type request struct {
		Secrets []string `json:"secrets"`
		Absent  []string `json:"absent,omitempty"`
	}
	for _, tc := range []struct {
		name string
		body any
		want string
	}{
		{name: "bodyless"},
		{name: "null", body: request{}, want: `{"secrets":null}`},
		{name: "empty", body: request{Secrets: []string{}}, want: `{"secrets":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/test?name=a%2Fb", r.RequestURI)
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "Bearer admin_test", r.Header.Get("Authorization"))
				assert.Equal(t, "tinfoil-cli/test-version", r.Header.Get("User-Agent"))
				assert.Equal(t, "application/json", r.Header.Get("Accept"))
				assert.Equal(t, "hf_test", r.Header.Get("X-Hugging-Face-Token"))
				if tc.body == nil {
					assert.Empty(t, r.Header.Get("Content-Type"))
				} else {
					assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				}
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, tc.want, string(body))
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, `{"result":"accepted"}`)
			}))
			defer server.Close()
			var out struct{ Result string }
			client := New(server.URL+"/", "test-version", server.Client(), tokens)
			status, err := client.Do(ctx, http.MethodPost, "/api/test", url.Values{"name": {"a/b"}}, map[string]string{"X-Hugging-Face-Token": "hf_test"}, tc.body, &out)
			require.NoError(t, err)
			require.Equal(t, http.StatusAccepted, status)
			require.Equal(t, "accepted", out.Result)
		})
	}
}

func TestErrorsRetainRawResponse(t *testing.T) {
	const body = `{"error":"select a volume for required slot","code":"VOLUME_REQUIRED"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	client := New(server.URL, "test", server.Client(), nil)
	status, err := client.Do(context.Background(), http.MethodPost, "/test", nil, nil, nil, nil)
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, &Error{Status: status, Method: http.MethodPost, Path: "/test", Code: "VOLUME_REQUIRED", Message: "select a volume for required slot", Body: []byte(body)}, apiErr)
	require.Equal(t, apiErr.Message, apiErr.Error())
}

func TestRefusesRedirectsWithSuppliedHTTPClient(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect must not reach another endpoint")
	}))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	custom := server.Client()
	custom.CheckRedirect = func(*http.Request, []*http.Request) error {
		t.Error("custom redirect policy must not bypass controlplane policy")
		return nil
	}
	client := New(server.URL, "test", custom, tokenSourceFunc(func(context.Context) (string, error) { return "admin_test", nil }))
	_, err := client.Do(context.Background(), http.MethodGet, "/redirect", nil, nil, nil, nil)
	require.ErrorContains(t, err, "refusing a controlplane redirect")
	require.NotNil(t, custom.CheckRedirect)
}

func TestValidatesURLBeforeObtainingCredentials(t *testing.T) {
	client := New("http://public.example", "test", nil, tokenSourceFunc(func(context.Context) (string, error) {
		t.Fatal("invalid transport must not request a credential")
		return "", nil
	}))
	_, err := client.Do(context.Background(), http.MethodGet, "/test", nil, nil, nil, nil)
	require.ErrorContains(t, err, "must use https")
}

func TestTokenSourceFailureAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("failed token request must not reach the server")
	}))
	defer server.Close()
	failure := errors.New("credential unavailable")
	client := New(server.URL, "test", server.Client(), tokenSourceFunc(func(context.Context) (string, error) { return "", failure }))
	_, err := client.Do(context.Background(), http.MethodGet, "/test", nil, nil, nil, nil)
	require.ErrorIs(t, err, failure)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client = New(server.URL, "test", server.Client(), tokenSourceFunc(func(ctx context.Context) (string, error) { return "", ctx.Err() }))
	_, err = client.Do(ctx, http.MethodGet, "/test", nil, nil, nil, nil)
	require.ErrorIs(t, err, context.Canceled)
}
