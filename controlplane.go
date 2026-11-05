package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
)

const controlplaneUserAgentPrefix = "tinfoil-cli/"

// Controlplane error codes for account limits, and the hint shown after them.
const (
	containerLimitReached = "CONTAINER_LIMIT_REACHED"
	sandboxLimitReached   = "SANDBOX_LIMIT_REACHED"
	storageLimitExceeded  = "STORAGE_LIMIT_EXCEEDED"
	accountLimitsHint     = "See your account limits in the Tinfoil dashboard."
	reloginHint           = "Run `tinfoil login` to sign in again."
)

type cpClient struct {
	baseURL string
	apiKey  string
	login   *clerkGrant
	http    *http.Client
}

func newCPClient(cfg cliConfig) *cpClient {
	return &cpClient{
		baseURL: strings.TrimRight(cfg.ControlplaneURL, "/"),
		apiKey:  cfg.APIKey,
		login:   cfg.login,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

type cpTokenSource struct{ client *cpClient }

func (s cpTokenSource) Token(ctx context.Context) (string, error) {
	if s.client.login != nil {
		return s.client.login.accessToken(ctx)
	}
	return s.client.apiKey, nil
}

// cpError carries a structured error from the controlplane.
type cpError controlplane.Error

func (e *cpError) Error() string {
	if e.Message != "" {
		return humanVolumeMessage(secretDeliveryMessage(e.Message))
	}
	return e.Unwrap().Error()
}

func (e *cpError) Unwrap() error { return (*controlplane.Error)(e) }

// errorHint returns a line to print after a failed command's error, or "".
// Commands wrap controlplane errors in their own context, so the hint is
// printed once at the end rather than inside the error text.
func errorHint(err error) string {
	var cp *controlplane.Error
	if !errors.As(err, &cp) {
		return ""
	}
	switch cp.Code {
	case containerLimitReached, sandboxLimitReached, storageLimitExceeded:
		return accountLimitsHint
	}
	if cp.Status == http.StatusUnauthorized {
		if source := credentialEnvSource(); source != "" {
			return fmt.Sprintf("Update or unset %s to sign in again.", source)
		}
		return reloginHint
	}
	return ""
}

// do performs an authenticated request against the controlplane. body may be
// nil. out may be nil to discard the response body. Returns the parsed status
// code on success, or a *cpError on non-2xx responses.
func (c *cpClient) do(method, path string, query url.Values, body any, out any) (int, error) {
	return c.doWithHeaders(method, path, query, nil, body, out)
}

// doWithHeaders is do with additional request headers, for endpoints that
// take out-of-band values such as a forwarded Hugging Face token.
func (c *cpClient) doWithHeaders(method, path string, query url.Values, headers map[string]string, body any, out any) (int, error) {
	return c.doContext(context.Background(), method, path, query, headers, body, out)
}

func (c *cpClient) doContext(ctx context.Context, method, path string, query url.Values, headers map[string]string, body any, out any) (int, error) {
	client := controlplane.New(c.baseURL, version, c.http, cpTokenSource{client: c})
	status, err := client.Do(ctx, method, path, query, headers, body, out)
	if apiErr, ok := err.(*controlplane.Error); ok {
		return status, (*cpError)(apiErr)
	}
	return status, err
}

func pathf(format string, segments ...string) string {
	return controlplane.Pathf(format, segments...)
}

func extractErrorMessage(body []byte) string {
	return controlplane.ErrorMessage(body)
}
