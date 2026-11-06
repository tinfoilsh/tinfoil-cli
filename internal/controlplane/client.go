package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	userAgentPrefix       = "tinfoil-cli/"
	defaultRequestTimeout = 60 * time.Second
)

type TokenSource interface {
	Token(context.Context) (string, error)
}

type Client struct {
	baseURL string
	version string
	tokens  TokenSource
	http    *http.Client
}

func New(baseURL, version string, client *http.Client, tokens TokenSource) *Client {
	httpClient := http.Client{Timeout: defaultRequestTimeout}
	if client != nil {
		httpClient = *client
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("refusing a controlplane redirect")
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		version: version,
		tokens:  tokens,
		http:    &httpClient,
	}
}

// Error carries a structured error from the controlplane.
type Error struct {
	Status  int
	Method  string
	Path    string
	Code    string
	Message string
	Body    []byte
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("controlplane returned HTTP %d for %s", e.Status, e.Path)
}

// Do performs an authenticated request against the controlplane. body may be
// nil. out may be nil to discard the response body. Returns the parsed status
// code on success, or an *Error on non-2xx responses.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, headers map[string]string, body any, out any) (int, error) {
	if err := ValidateURL(c.baseURL); err != nil {
		return 0, err
	}
	u := c.baseURL + path
	if query != nil {
		u += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encoding request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return 0, fmt.Errorf("building request: %w", err)
	}
	var token string
	if c.tokens != nil {
		if token, err = c.tokens.Token(ctx); err != nil {
			return 0, err
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentPrefix+c.version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("controlplane request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return resp.StatusCode, &Error{
			Status:  resp.StatusCode,
			Method:  method,
			Path:    path,
			Code:    extractErrorCode(respBody),
			Message: ErrorMessage(respBody),
			Body:    respBody,
		}
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Pathf builds a controlplane URL path by url.PathEscape-ing each segment
// before substituting it into the printf-style format. Use this anywhere a
// path component comes from user input or unverified server data. Callers must
// still reject exact `.` and `..` segments, which PathEscape leaves unchanged.
func Pathf(format string, segments ...string) string {
	args := make([]any, len(segments))
	for i, s := range segments {
		args[i] = url.PathEscape(s)
	}
	return fmt.Sprintf(format, args...)
}

// ErrorMessage best-effort decodes controlplane error payloads which
// usually look like {"error":"..."} or {"message":"..."}.
func ErrorMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		for _, key := range []string{"error", "message"} {
			if v, ok := m[key].(string); ok && v != "" {
				return v
			}
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// extractErrorCode returns the machine-readable code of a controlplane error
// payload such as {"error":"...","code":"SANDBOX_LIMIT_REACHED"}, or "".
func extractErrorCode(body []byte) string {
	var detail struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &detail) != nil {
		return ""
	}
	return detail.Code
}
