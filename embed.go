package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// EmbedResponse contains the embeddings response in OpenAI format.
type EmbedResponse struct {
	Object string `json:"object"`
	Data   []struct {
		Object    string    `json:"object"`
		Embedding []float64 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
}

var embedModel string

func init() {
	rootCmd.AddCommand(embedCmd)
	// Support both model and API key flags (enclave host and repo are global)
	embedCmd.Flags().StringVarP(&embedModel, "model", "m", "nomic-embed-text", "Model name for embeddings (default: nomic-embed-text)")
	embedCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
}

var embedCmd = &cobra.Command{
	Use:   "embed [input]",
	Short: "Generate embeddings for the provided text input(s)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// If enclaveHost or repo are not provided via flags,
		// try to load them from the embedded config for the given model.
		if enclaveHost == "" || repo == "" {
			models, err := loadDefaultConfig()
			if err != nil {
				log.Printf("Error loading default config: %v", err)
				os.Exit(1)
			}

			selectedModel, ok := models[embedModel]
			if !ok {
				log.Printf("No config found for model %s: %v", embedModel, err)
				log.Printf("Please specify -e and -r flags for custom models")
				os.Exit(1)
			}
			enclaveHost = selectedModel.Enclave
			repo = selectedModel.Repo
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

		// Construct the URL for the /v1/embeddings endpoint.
		url := fmt.Sprintf("https://%s/v1/embeddings", enclaveHost)
		sc := secureClient()

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
		}

		client, err := sc.HTTPClient()
		if err != nil {
			log.Fatalf("Error getting HTTP client: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error performing request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			bodyText, _ := io.ReadAll(resp.Body)
			log.Fatalf("Enclave returned status code %d: %s", resp.StatusCode, string(bodyText))
		}

		var embedResp EmbedResponse
		if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
			log.Fatalf("Error decoding response: %v", err)
		}

		// Extract just the embeddings from the response
		var embeddings [][]float64
		for _, item := range embedResp.Data {
			embeddings = append(embeddings, item.Embedding)
		}

		// Print only the embeddings list as JSON.
		output, err := json.MarshalIndent(embeddings, "", "  ")
		if err != nil {
			log.Fatalf("Error formatting output: %v", err)
		}
		fmt.Println(string(output))
	},
}
