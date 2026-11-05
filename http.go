package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tinfoilsh/tinfoil-go"
)

func secureClient(rootOpts *rootOptions) (*tinfoil.EnclaveHTTPClient, error) {
	return newVerifiedClient(rootOpts, rootOpts.enclaveHost, rootOpts.repo, "")
}

func requestWithHeaders(sc *tinfoil.EnclaveHTTPClient, method, url string, headers map[string]string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return sc.Do(req)
}

func printHTTPResponse(out io.Writer, body io.Reader) error {
	if _, err := io.Copy(out, body); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out)
	return err
}

func newHttpCommand(headersOpts *headersOptions, rootOpts *rootOptions) *cobra.Command {
	httpCmd := &cobra.Command{
		Use:   "http",
		Short: "Make verified HTTP requests",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if rootOpts.enclaveHost == "" || rootOpts.repo == "" && rootOpts.localConfigFile == "" {
				return fmt.Errorf("--enclave and either --repo or --config are required for verified HTTP requests")
			}
			return nil
		},
	}
	httpCmd.PersistentFlags().StringArrayVarP(&headersOpts.requestHeaders, "header", "H", nil, `HTTP request header ("Name: Value"); may be repeated`)
	httpCmd.AddCommand(newHttpGetCommand(headersOpts, rootOpts))
	httpCmd.AddCommand(newHttpPostCommand(headersOpts, &httpPostOptions{}, rootOpts))
	return httpCmd
}

func parseRequestHeaders(headerArgs []string) (map[string]string, error) {
	if len(headerArgs) == 0 {
		return nil, nil
	}

	headers := make(map[string]string, len(headerArgs))
	for _, raw := range headerArgs {
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q: expected \"Name: Value\"", raw)
		}

		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("invalid header %q: header name cannot be empty", raw)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("invalid header %q: headers cannot contain newlines", raw)
		}

		headers[name] = value
	}

	return headers, nil
}

func hasRequestHeader(headers map[string]string, name string) bool {
	for headerName := range headers {
		if strings.EqualFold(headerName, name) {
			return true
		}
	}
	return false
}
