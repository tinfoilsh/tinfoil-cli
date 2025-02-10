// File: http_post.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/spf13/cobra"
)

var body string
var stream bool

func init() {
	// Register flags: -b for body and -s for streaming
	httpPostCmd.Flags().StringVarP(&body, "body", "b", "", "HTTP POST body")
	httpPostCmd.Flags().BoolVarP(&stream, "stream", "s", false, "Stream response output")
	httpCmd.AddCommand(httpPostCmd)
}

var httpPostCmd = &cobra.Command{
	Use:   "post [url]",
	Short: "HTTP POST request",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		sc := secureClient() // Returns a *client.SecureClient

		// Branch based on the --stream flag.
		if stream {
			// Build a raw HTTP POST request with the provided body.
			req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
			if err != nil {
				log.Fatalf("Error creating request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Use the verifier’s HTTP client.
			client, err := sc.HTTPClient()
			if err != nil {
				log.Fatalf("Error getting HTTP client: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Fatalf("Error performing streaming request: %v", err)
			}
			defer resp.Body.Close()

			// Read the response body incrementally (for example, line by line).
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				log.Fatalf("Error reading stream: %v", err)
			}
		} else {
			// Non-streaming: use the existing Post method which reads the full response.
			resp, err := sc.Post(url, nil, []byte(body))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(resp.Body))
		}
	},
}
