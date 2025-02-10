package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

// Embed the config.json file that is checked into the repository.
//
//go:embed config.json
var configData []byte

// ChatMessage represents a single message in the conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the payload sent to the chat API.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// ChatResponse represents one JSON chunk in the streaming response.
type ChatResponse struct {
	Message ChatMessage `json:"message"`
	Done    bool        `json:"done"`
}

var modelName string

func init() {
	rootCmd.AddCommand(chatCmd)
	// Add a flag for the model name, defaulting to deepseek-r1:70b.
	chatCmd.Flags().StringVarP(&modelName, "model", "m", "deepseek-r1:70b", "Model name (default deepseek-r1:70b)")
}

var chatCmd = &cobra.Command{
	Use:   "chat [prompt]",
	Short: "Chat with the model using a simple prompt",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Combine the arguments to form the prompt.
		prompt := strings.Join(args, " ")

		// If either enclaveHost or repo is not provided via flags,
		// try to load them from the embedded JSON config.
		if enclaveHost == "" || repo == "" {
			loadedHost, loadedRepo, err := loadDefaultConfig(modelName)
			if err != nil {
				log.Printf("No config found for model %s: %v", modelName, err)
				log.Printf("Please specify -e and -r flags for custom models")
			} else {
				enclaveHost = loadedHost
				repo = loadedRepo
			}
		}

		// Build the JSON request payload.
		reqPayload := ChatRequest{
			Model: modelName,
			Messages: []ChatMessage{
				{Role: "system", Content: "You are a helpful assistant."},
				{Role: "user", Content: prompt},
			},
			Stream: true,
		}

		payloadBytes, err := json.Marshal(reqPayload)
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}

		// Construct the URL using the enclave host.
		url := fmt.Sprintf("https://%s/api/chat", enclaveHost)
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

		// Stream the response, printing only the assistant's text.
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			var chatResp ChatResponse
			if err := json.Unmarshal([]byte(line), &chatResp); err != nil {
				// Skip lines that don’t match our expected JSON.
				continue
			}
			fmt.Print(chatResp.Message.Content)
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading stream: %v", err)
		}
	},
}

// loadDefaultConfig reads the embedded JSON configuration and returns the enclave host and repo
// values for the given model.
func loadDefaultConfig(model string) (string, string, error) {
	// Define a map where keys are model names.
	var cfg map[string]struct {
		EnclaveHost string `json:"enclave_host"`
		Repo        string `json:"repo"`
	}

	if err := json.Unmarshal(configData, &cfg); err != nil {
		return "", "", err
	}
	if modelCfg, ok := cfg[model]; ok {
		return modelCfg.EnclaveHost, modelCfg.Repo, nil
	}
	return "", "", fmt.Errorf("no configuration found for model: %s", model)
}
