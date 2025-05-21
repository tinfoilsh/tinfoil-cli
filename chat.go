package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

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
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type Choice struct {
	Index        int    `json:"index"`
	Delta        Delta  `json:"delta"`
	FinishReason string `json:"finish_reason"`
}

type Delta struct {
	Content string `json:"content"`
}

var (
	modelName, apiKey string
	listModels        bool
)

func init() {
	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().StringVarP(&modelName, "model", "m", "", "Model name")
	chatCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	chatCmd.Flags().BoolVarP(&listModels, "list", "l", false, "List available models")
}

var chatCmd = &cobra.Command{
	Use:   "chat [prompt]",
	Short: "Chat with the model using a simple prompt",
	Run: func(cmd *cobra.Command, args []string) {
		models, err := loadDefaultConfig()
		if err != nil {
			log.Fatalf("Error loading default config: %v", err)
		}

		if listModels {
			for modelName := range models {
				fmt.Println(modelName)
			}
			return
		}

		if len(args) == 0 {
			log.Fatalf("Please provide a prompt")
		}

		prompt := strings.Join(args, " ")

		if enclaveHost == "" || repo == "" {
			selectedModel, ok := models[modelName]
			if !ok {
				log.Printf("Error: Configuration not found for model '%s'", modelName)
				log.Printf("The model '%s' is not in the default configuration. To use this model, please provide:", modelName)
				log.Printf("  1. The enclave host with the -e flag (e.g., -e %s.model.tinfoil.sh)", modelName)
				log.Printf("  2. The source repository with the -r flag (e.g., -r tinfoilsh/confidential-%s)", modelName)
				log.Printf("Example: tinfoil chat -m %s -e <enclave-host> -r <repo> -k <api-key> \"Your prompt\"", modelName)
				log.Fatalf("Aborting due to missing configuration")
			} else {
				enclaveHost = selectedModel.Enclave
				repo = selectedModel.Repo
			}
		}

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

		url := fmt.Sprintf("https://%s/v1/chat/completions", enclaveHost)
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
			bodyText, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("Error reading response body: %v", err)
			}
			log.Fatalf("Enclave returned status code %d: %s", resp.StatusCode, string(bodyText))
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()

			if len(line) == 0 {
				continue
			}

			line = strings.TrimPrefix(line, "data: ")
			if line == "[DONE]" || line == "" {
				continue
			}

			var response ChatResponse
			if err := json.Unmarshal([]byte(line), &response); err != nil {
				fmt.Println(line)
				continue
			}

			if len(response.Choices) > 0 && response.Choices[0].Delta.Content != "" {
				fmt.Print(response.Choices[0].Delta.Content)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading stream: %v", err)
		}
	},
}

type model struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
}

// loadDefaultConfig reads the embedded JSON configuration and returns the config structure
func loadDefaultConfig() (map[string]model, error) {
	cfg := make(map[string]model)
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
