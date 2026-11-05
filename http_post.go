package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

func newHttpPostCommand(headersOpts *headersOptions, httpPostOpts *httpPostOptions, rootOpts *rootOptions) *cobra.Command {
	httpPostCmd := &cobra.Command{
		Use:   "post [url]",
		Short: "HTTP POST request",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			sc, err := secureClient(rootOpts)
			if err != nil {
				return err
			}

			headers, err := parseRequestHeaders(headersOpts.requestHeaders)
			if err != nil {
				return err
			}

			if httpPostOpts.stream {
				// Build a raw HTTP POST request with the provided body.
				req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(httpPostOpts.body)))
				if err != nil {
					return fmt.Errorf("error creating request: %w", err)
				}
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				if !hasRequestHeader(headers, "Content-Type") {
					req.Header.Set("Content-Type", "application/json")
				}

				// Use the verifier’s HTTP client.
				client := sc
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("error performing streaming request: %w", err)
				}
				defer resp.Body.Close()

				scanner := bufio.NewScanner(resp.Body)
				for scanner.Scan() {
					fmt.Println(scanner.Text())
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("error reading stream: %w", err)
				}
			} else { // Not streaming
				resp, err := requestWithHeaders(sc, "POST", url, headers, []byte(httpPostOpts.body))
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if err := printHTTPResponse(cmd.OutOrStdout(), resp.Body); err != nil {
					return err
				}
			}

			return nil
		},
	}
	httpPostCmd.Flags().StringVarP(&httpPostOpts.body, "body", "b", "", "HTTP POST body")
	httpPostCmd.Flags().BoolVarP(&httpPostOpts.stream, "stream", "s", false, "Stream response output")
	return httpPostCmd
}
