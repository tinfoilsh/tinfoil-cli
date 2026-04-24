package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var (
	body   string
	stream bool
)

func init() {
	httpPostCmd.Flags().StringVarP(&body, "body", "b", "", "HTTP POST body")
	httpPostCmd.Flags().BoolVarP(&stream, "stream", "s", false, "Stream response output")
	httpCmd.AddCommand(httpPostCmd)
}

var httpPostCmd = &cobra.Command{
	Use:   "post [url]",
	Short: "HTTP POST request",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url := args[0]
		sc := secureClient()

		headers, err := parseRequestHeaders(requestHeaders)
		if err != nil {
			return err
		}

		if stream {
			// Build a raw HTTP POST request with the provided body.
			req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
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
			client, err := sc.HTTPClient()
			if err != nil {
				return fmt.Errorf("error getting HTTP client: %w", err)
			}
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
			resp, err := sc.Post(url, headers, []byte(body))
			if err != nil {
				return err
			}
			fmt.Println(string(resp.Body))
		}

		return nil
	},
}
