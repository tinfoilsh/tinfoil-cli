package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// EmbedRequest is the payload sent to the embeddings API.
type EmbedRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"`
}

// EmbedResponse contains just the embeddings list from the API.
type EmbedResponse struct {
	Embeddings [][]float64 `json:"embeddings"`
}

var embedModel string

func init() {
	rootCmd.AddCommand(embedCmd)
	// Only support the model flag (enclave host and repo are global)
	embedCmd.Flags().StringVarP(&embedModel, "model", "m", "nomic-embed-text", "Model name for embeddings (default: nomic-embed-text)")
}

var embedCmd = &cobra.Command{
	Use:   "embed [input]",
	Short: "Generate embeddings for the provided text input(s)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// If enclaveHost or repo are not provided via flags,
		// try to load them from the embedded config for the given model.
		if enclaveHost == "" || repo == "" {
			loadedHost, loadedRepo, err := loadDefaultConfig(embedModel)
			if err != nil {
				log.Printf("No config found for model %s: %v", embedModel, err)
				log.Printf("Please specify -e and -r flags for custom models")
				os.Exit(1)
			}
			enclaveHost = loadedHost
			repo = loadedRepo
		}

		// Support both a single input (string) and multiple inputs (slice of strings)
		var input interface{}
		if len(args) == 1 {
			input = args[0]
		} else {
			input = args
		}

		reqPayload := EmbedRequest{
			Model: embedModel,
			Input: input,
		}

		payloadBytes, err := json.Marshal(reqPayload)
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}

		// Construct the URL for the /api/embed endpoint.
		url := fmt.Sprintf("https://%s/api/embed", enclaveHost)
		sc := secureClient()

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		client, err := sc.HTTPClient()
		if err != nil {
			log.Fatalf("Error getting HTTP client: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error performing request: %v", err)
		}
		defer resp.Body.Close()

		var embedResp EmbedResponse
		if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
			log.Fatalf("Error decoding response: %v", err)
		}

		// Print only the embeddings list as JSON.
		output, err := json.MarshalIndent(embedResp.Embeddings, "", "  ")
		if err != nil {
			log.Fatalf("Error formatting output: %v", err)
		}
		fmt.Println(string(output))
	},
}
