package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var requestHeaders []string

func secureClient() *client.SecureClient {
	return client.NewSecureClient(enclaveHost, repo)
}

func init() {
	rootCmd.AddCommand(httpCmd)
	httpCmd.PersistentFlags().StringArrayVarP(&requestHeaders, "header", "H", nil, `HTTP request header ("Name: Value"); may be repeated`)
}

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Make verified HTTP requests",
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
