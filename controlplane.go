package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type cpClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newCPClient(cfg cliConfig) *cpClient {
	return &cpClient{
		baseURL: strings.TrimRight(cfg.ControlplaneURL, "/"),
		apiKey:  cfg.APIKey,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// cpError carries a structured error from the controlplane.
type cpError struct {
	Status  int
	Method  string
	Path    string
	Message string
	Body    []byte
}

func (e *cpError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s %s: %d: %s", e.Method, e.Path, e.Status, e.Message)
	}
	return fmt.Sprintf("%s %s: %d", e.Method, e.Path, e.Status)
}

// do performs an authenticated request against the controlplane. body may be
// nil. out may be nil to discard the response body. Returns the parsed status
// code on success, or a *cpError on non-2xx responses.
func (c *cpClient) do(method, path string, query url.Values, body any, out any) (int, error) {
	if err := validateControlplaneURL(c.baseURL); err != nil {
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

	req, err := http.NewRequest(method, u, reader)
	if err != nil {
		return 0, fmt.Errorf("building request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

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
		return resp.StatusCode, &cpError{
			Status:  resp.StatusCode,
			Method:  method,
			Path:    path,
			Message: extractErrorMessage(respBody),
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

// pathf builds a controlplane URL path by url.PathEscape-ing each segment
// before substituting it into the printf-style format. Use this anywhere a
// path component comes from user input or unverified server data — string
// concatenation would let `..` or `/` in a name traverse to a different
// endpoint than the one the command names.
func pathf(format string, segments ...string) string {
	args := make([]any, len(segments))
	for i, s := range segments {
		args[i] = url.PathEscape(s)
	}
	return fmt.Sprintf(format, args...)
}

// extractErrorMessage best-effort decodes controlplane error payloads which
// usually look like {"error":"..."} or {"message":"..."}.
func extractErrorMessage(body []byte) string {
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
