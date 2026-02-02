package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go"
)

// Proxy constants - all inference requests go through this proxy
const (
	PROXY_ENCLAVE = "inference.tinfoil.sh"
	PROXY_REPO    = "tinfoilsh/confidential-model-router"
)

//go:embed config.json
var configFS embed.FS
var configData []byte

// ChatMessage represents a single message in a chat conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is sent to the /v1/chat/completions endpoint.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// WhisperRequest is sent to the /v1/audio/transcriptions endpoint.
type WhisperRequest struct {
	Model string `json:"model"`
	File  string `json:"file"`
}

// ChatResponse represents the response from the chat completions API (both streaming and non-streaming).
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type Choice struct {
	Index        int          `json:"index"`
	Delta        *Delta       `json:"delta,omitempty"`   // Used in streaming
	Message      *ChatMessage `json:"message,omitempty"` // Used in non-streaming
	FinishReason string       `json:"finish_reason"`
}

type Delta struct {
	Content string `json:"content"`
}

var (
	modelName, apiKey string
	listModels        bool
	streamChat        bool
	audioFile         string
	ttsText           string
	ttsVoice          string
	outputFile        string
)

// loadDefaultConfig unmarshals the embedded config.json for model name mapping.
func loadDefaultConfig() (map[string]string, error) {
	cfg := make(map[string]string)
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

	// Chat command
	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().StringVarP(&modelName, "model", "m", "", "Model name")
	chatCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	chatCmd.Flags().BoolVarP(&listModels, "list", "l", false, "List available chat models")
	chatCmd.Flags().BoolVarP(&streamChat, "stream", "s", false, "Stream response output")

	// Audio command (for transcription)
	rootCmd.AddCommand(audioCmd)
	audioCmd.Flags().StringVarP(&modelName, "model", "m", "whisper-large-v3-turbo", "Model name (default: whisper-large-v3-turbo)")
	audioCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	audioCmd.Flags().StringVarP(&audioFile, "file", "f", "", "Audio file to transcribe")

	// TTS command (for text-to-speech synthesis)
	rootCmd.AddCommand(ttsCmd)
	ttsCmd.Flags().StringVarP(&modelName, "model", "m", "kokoro", "Model name (default: kokoro)")
	ttsCmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API key")
	ttsCmd.Flags().StringVar(&ttsVoice, "voice", "af_sky+af_bella", "Voice to use for synthesis (default: af_sky+af_bella)")
	ttsCmd.Flags().StringVarP(&outputFile, "output", "o", "output.mp3", "Output file path (default: output.mp3)")
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
			for mn := range models {
				if strings.HasPrefix(mn, "whisper") || mn == "kokoro" {
					// Exclude audio models from chat listing.
					continue
				}
				fmt.Println(mn)
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
			// Resolve model name alias if it exists
			if resolvedModel, ok := models[modelName]; ok {
				modelName = resolvedModel
			}
			// Always use proxy constants
			enclaveHost = PROXY_ENCLAVE
			repo = PROXY_REPO
		}

		handleChatInference(strings.Join(args, " "), streamChat)
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

		if !strings.HasPrefix(modelName, "whisper") && !strings.HasPrefix(modelName, "voxtral") {
			log.Fatalf("Invalid model. Must use a whisper or voxtral model for audio transcription")
		}

		if enclaveHost == "" || repo == "" {
			// Resolve model name alias if it exists
			if resolvedModel, ok := models[modelName]; ok {
				modelName = resolvedModel
			}
			// Always use proxy constants
			enclaveHost = PROXY_ENCLAVE
			repo = PROXY_REPO
		}

		handleWhisperInference()
	},
}

var ttsCmd = &cobra.Command{
	Use:   "tts [text]",
	Short: "Convert text to speech using TTS models",
	Run: func(cmd *cobra.Command, args []string) {
		models, err := loadDefaultConfig()
		if err != nil {
			log.Fatalf("Error loading default config: %v", err)
		}

		if len(args) == 0 {
			log.Fatalf("Please provide text to convert to speech")
		}

		ttsText = strings.Join(args, " ")

		if enclaveHost == "" || repo == "" {
			// Resolve model name alias if it exists
			if resolvedModel, ok := models[modelName]; ok {
				modelName = resolvedModel
			}
			// Always use proxy constants
			enclaveHost = PROXY_ENCLAVE
			repo = PROXY_REPO
		}

		handleTTSInference()
	},
}

// handleChatInference handles chat completion responses from the enclave, with optional streaming.
func handleChatInference(prompt string, stream bool) {
	reqPayload := ChatRequest{
		Model:    modelName,
		Messages: []ChatMessage{{Role: "system", Content: "You are a helpful assistant."}, {Role: "user", Content: prompt}},
		Stream:   stream,
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
		bodyText, _ := io.ReadAll(resp.Body)
		log.Fatalf("Enclave returned status code %d: %s", resp.StatusCode, string(bodyText))
	}

	if stream {
		// Handle streaming response
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
				// If the chunk cannot be parsed just print raw line for debugging.
				fmt.Println(line)
				continue
			}

			if len(response.Choices) > 0 && response.Choices[0].Delta != nil && response.Choices[0].Delta.Content != "" {
				fmt.Print(response.Choices[0].Delta.Content)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading stream: %v", err)
		}
		fmt.Println() // Add newline at the end of streaming
	} else {
		// Handle non-streaming response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}

		var response ChatResponse
		if err := json.Unmarshal(bodyBytes, &response); err != nil {
			log.Fatalf("Error parsing JSON response: %v", err)
		}

		if len(response.Choices) > 0 && response.Choices[0].Message != nil {
			fmt.Println(response.Choices[0].Message.Content)
		}
	}
}

// handleWhisperInference uploads an audio file and prints the transcription.
func handleWhisperInference() {
	if audioFile == "" {
		log.Fatalf("Audio file is required for whisper models. Use the --file flag.")
	}

	client, err := tinfoil.NewClientWithParams(
		enclaveHost,
		repo,
		option.WithAPIKey(apiKey),
	)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	audioFileReader, err := os.Open(audioFile)
	if err != nil {
		log.Fatalf("Error opening audio file: %v", err)
	}

	resp, err := client.Audio.Transcriptions.New(
		context.Background(),
		openai.AudioTranscriptionNewParams{
			File:  audioFileReader,
			Model: modelName,
		},
	)
	if err != nil {
		log.Fatalf("Error transcribing audio: %v", err)
	}

	fmt.Println(resp.Text)
}

// handleTTSInference converts text to speech and saves the audio file.
func handleTTSInference() {
	client, err := tinfoil.NewClientWithParams(
		enclaveHost,
		repo,
		option.WithAPIKey(apiKey),
	)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	response, err := client.Audio.Speech.New(
		context.Background(),
		openai.AudioSpeechNewParams{
			Model: openai.AudioModel(modelName),
			Voice: openai.AudioSpeechNewParamsVoice(ttsVoice),
			Input: ttsText,
		},
	)
	if err != nil {
		log.Fatalf("Error creating speech: %v", err)
	}
	defer response.Body.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, response.Body)
	if err != nil {
		log.Fatalf("Error writing audio file: %v", err)
	}

	fmt.Printf("Speech saved to %s\n", outputFile)
}

// handleChatInferenceWithPayload handles chat completion with a custom payload (for interactive mode)
func handleChatInferenceWithPayload(reqPayload ChatRequest) (string, error) {
	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %w", err)
	}

	url := fmt.Sprintf("https://%s/v1/chat/completions", enclaveHost)
	sc := secureClient()

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	}

	client, err := sc.HTTPClient()
	if err != nil {
		return "", fmt.Errorf("error getting HTTP client: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyText, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("enclave returned status code %d: %s", resp.StatusCode, string(bodyText))
	}

	if reqPayload.Stream {
		// Handle streaming response
		scanner := bufio.NewScanner(resp.Body)
		var responseContent strings.Builder

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
				// If the chunk cannot be parsed just print raw line for debugging.
				fmt.Print(line)
				continue
			}

			if len(response.Choices) > 0 && response.Choices[0].Delta != nil && response.Choices[0].Delta.Content != "" {
				content := response.Choices[0].Delta.Content
				fmt.Print(content)
				responseContent.WriteString(content)
			}
		}

		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading stream: %w", err)
		}

		return responseContent.String(), nil
	} else {
		// Handle non-streaming response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error reading response body: %w", err)
		}

		var response ChatResponse
		if err := json.Unmarshal(bodyBytes, &response); err != nil {
			return "", fmt.Errorf("error parsing JSON response: %w", err)
		}

		if len(response.Choices) > 0 && response.Choices[0].Message != nil {
			content := response.Choices[0].Message.Content
			fmt.Print(content)
			return content, nil
		}

		return "", nil
	}
}
