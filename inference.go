package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed config.json
var configFS embed.FS
var configData []byte

type model struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
}

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

// WhisperRequest is the payload sent to the audio transcription API.
type WhisperRequest struct {
	Model string `json:"model"`
	File  string `json:"file"`
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
	audioFile         string
)

// loadDefaultConfig reads the embedded JSON configuration and returns the config structure
func loadDefaultConfig() (map[string]model, error) {
	cfg := make(map[string]model)
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func init() {
	var err error
	configData, err = configFS.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Error reading config.json: %v", err)
	}

	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().StringVarP(&modelName, "model", "m", "", "Model name")
	chatCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	chatCmd.Flags().BoolVarP(&listModels, "list", "l", false, "List available chat models")

	rootCmd.AddCommand(audioCmd)
	audioCmd.Flags().StringVarP(&modelName, "model", "m", "whisper-large-v3-turbo", "Model name (default: whisper-large-v3-turbo)")
	audioCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	audioCmd.Flags().StringVarP(&audioFile, "file", "f", "", "Audio file to transcribe")
}

var chatCmd = &cobra.Command{
	Use:   "chat [prompt]",
	Short: "Chat with a language model",
	Run: func(cmd *cobra.Command, args []string) {
		models, err := loadDefaultConfig()
		if err != nil {
			log.Fatalf("Error loading default config: %v", err)
		}

		if listModels {
			for modelName := range models {
				if !strings.HasPrefix(modelName, "whisper") {
					fmt.Println(modelName)
				}
			}
			return
		}

		if len(args) == 0 {
			log.Fatalf("Please provide a prompt")
		}

		if modelName == "" {
			log.Fatalf("Please specify a model using the -m flag")
		}

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

		handleChatInference(strings.Join(args, " "))
	},
}

var audioCmd = &cobra.Command{
	Use:   "audio",
	Short: "Transcribe audio files using Whisper",
	Run: func(cmd *cobra.Command, args []string) {
		models, err := loadDefaultConfig()
		if err != nil {
			log.Fatalf("Error loading default config: %v", err)
		}

		if audioFile == "" {
			log.Fatalf("Please specify an audio file using the -f flag")
		}

		if !strings.HasPrefix(modelName, "whisper") {
			log.Fatalf("Invalid model. Must use a whisper model for audio transcription")
		}

		if enclaveHost == "" || repo == "" {
			selectedModel, ok := models[modelName]
			if !ok {
				log.Printf("Error: Configuration not found for model '%s'", modelName)
				log.Printf("The model '%s' is not in the default configuration. To use this model, please provide:", modelName)
				log.Printf("  1. The enclave host with the -e flag (e.g., -e %s.model.tinfoil.sh)", modelName)
				log.Printf("  2. The source repository with the -r flag (e.g., -r tinfoilsh/confidential-%s)", modelName)
				log.Printf("Example: tinfoil audio -f audio.mp3 -m %s -e <enclave-host> -r <repo> -k <api-key>", modelName)
				log.Fatalf("Aborting due to missing configuration")
			} else {
				enclaveHost = selectedModel.Enclave
				repo = selectedModel.Repo
			}
		}

		handleWhisperInference()
	},
}

func handleChatInference(prompt string) {
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
}

func handleWhisperInference() {
	if audioFile == "" {
		log.Fatalf("Audio file is required for whisper models. Use the --file flag.")
	}

	file, err := os.Open(audioFile)
	if err != nil {
		log.Fatalf("Error opening audio file: %v", err)
	}
	defer file.Close()

	url := fmt.Sprintf("https://%s/v1/audio/transcriptions", enclaveHost)
	sc := secureClient()

	// Create multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", audioFile)
	if err != nil {
		log.Fatalf("Error creating form file: %v", err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		log.Fatalf("Error copying file to form: %v", err)
	}
	writer.WriteField("model", modelName)
	writer.Close()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
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

	var result struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Error decoding response: %v", err)
	}

	fmt.Println(result.Text)
}
