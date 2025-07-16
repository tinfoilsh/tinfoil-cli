package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const tinfoilASCII = `
████████╗██╗███╗   ██╗███████╗ ██████╗ ██╗██╗     
╚══██╔══╝██║████╗  ██║██╔════╝██╔═══██╗██║██║     
   ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██║██║     
   ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██║██║     
   ██║   ██║██║ ╚████║██║     ╚██████╔╝██║███████╗
   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝╚══════╝`


type ChatSession struct {
	messages     []ChatMessage
	currentModel string
	models       map[string]string
	apiKey       string
}

func NewChatSession() *ChatSession {
	models, err := loadDefaultConfig()
	if err != nil {
		models = make(map[string]string)
	}
	return &ChatSession{
		messages: []ChatMessage{{Role: "system", Content: "You are a helpful assistant."}},
		models:   models,
	}
}

func (cs *ChatSession) addMessage(role, content string) {
	cs.messages = append(cs.messages, ChatMessage{Role: role, Content: content})
}

func (cs *ChatSession) setModel(model string) {
	if resolvedModel, ok := cs.models[model]; ok {
		cs.currentModel = resolvedModel
	} else {
		cs.currentModel = model
	}
}

func (cs *ChatSession) listModels() {
	fmt.Println("\nAvailable models:")
	
	// Define chat models with friendly names in order
	chatModels := []struct {
		alias       string
		friendlyName string
	}{
		{"llama", "Llama 3.3 70B"},
		{"deepseek", "DeepSeek R1 70B"},
		{"mistral", "Mistral Small 3.1 24B"},
		{"qwen", "Qwen 2.5 72B"},
	}
	
	for i, model := range chatModels {
		if resolvedModel, exists := cs.models[model.alias]; exists {
			if cs.currentModel == resolvedModel || cs.currentModel == model.alias {
				fmt.Printf("  %d. %s - %s [current]\n", i+1, model.alias, model.friendlyName)
			} else {
				fmt.Printf("  %d. %s - %s\n", i+1, model.alias, model.friendlyName)
			}
		}
	}
	fmt.Println()
}

func (cs *ChatSession) getModelByNumber(number int) string {
	chatModels := []string{"llama", "deepseek", "mistral", "qwen"}
	if number >= 1 && number <= len(chatModels) {
		return chatModels[number-1]
	}
	return ""
}

func (cs *ChatSession) handleCommand(input string) bool {
	switch {
	case input == "/models":
		cs.listModels()
		return true
	case strings.HasPrefix(input, "/model "):
		numberStr := strings.TrimSpace(strings.TrimPrefix(input, "/model "))
		if numberStr == "" {
			fmt.Println("Usage: /model <number>")
			fmt.Println("Use /models to see available models with their numbers")
			return true
		}
		
		// Parse the number
		var number int
		if _, err := fmt.Sscanf(numberStr, "%d", &number); err != nil {
			fmt.Println("Please enter a valid number. Use /models to see available models.")
			return true
		}
		
		model := cs.getModelByNumber(number)
		if model == "" {
			fmt.Println("Invalid model number. Use /models to see available models.")
			return true
		}
		
		cs.setModel(model)
		fmt.Printf("Switched to model: %s\n", model)
		fmt.Println()
		return true
	case input == "/help":
		cs.showHelp()
		return true
	case input == "/clear":
		cs.messages = []ChatMessage{{Role: "system", Content: "You are a helpful assistant."}}
		fmt.Println("Chat history cleared!")
		fmt.Println()
		return true
	case input == "/exit" || input == "/quit":
		fmt.Println("Goodbye!")
		os.Exit(0)
		return true
	}
	return false
}

func (cs *ChatSession) showHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  /models          - List available models")
	fmt.Println("  /model <number>  - Switch to a specific model by number")
	fmt.Println("  /clear           - Clear chat history")
	fmt.Println("  /help            - Show this help message")
	fmt.Println("  /exit, /quit     - Exit the chat")
	fmt.Println()
	fmt.Println("Just type your message and press Enter to chat!")
}

func (cs *ChatSession) sendMessage(content string) {
	if cs.currentModel == "" {
		fmt.Println("No model selected. Use '/models' to see available models and '/model <number>' to select one.")
		return
	}

	cs.addMessage("user", content)

	// Set up proxy constants
	if enclaveHost == "" || repo == "" {
		enclaveHost = PROXY_ENCLAVE
		repo = PROXY_REPO
	}

	// Use the existing handleChatInference function with streaming enabled
	modelName = cs.currentModel
	apiKey = cs.apiKey
	fmt.Println() // Add space before response
	
	// Create a new request with the full conversation history
	reqPayload := ChatRequest{
		Model:    cs.currentModel,
		Messages: cs.messages,
		Stream:   true,
	}
	
	// Call the streaming chat function and capture response
	response := handleChatInferenceWithPayload(reqPayload)
	if response != "" {
		cs.addMessage("assistant", response)
	}
	fmt.Println() // Add space after response
}

func (cs *ChatSession) getAPIKeyCacheFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".tinfoil-api-key")
}

func (cs *ChatSession) loadCachedAPIKey() bool {
	cacheFile := cs.getAPIKeyCacheFile()
	if cacheFile == "" {
		return false
	}
	
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return false
	}
	
	cs.apiKey = strings.TrimSpace(string(data))
	return cs.apiKey != ""
}

func (cs *ChatSession) saveAPIKey() {
	cacheFile := cs.getAPIKeyCacheFile()
	if cacheFile == "" || cs.apiKey == "" {
		return
	}
	
	// Create file with restricted permissions (600)
	file, err := os.OpenFile(cacheFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	
	file.WriteString(cs.apiKey)
}

func (cs *ChatSession) promptForAPIKey() {
	// Try to load cached API key first
	if cs.loadCachedAPIKey() {
		fmt.Println("Using cached API key...")
		return
	}
	
	fmt.Print("Enter your API key: ")
	
	// Check if we're in a terminal (interactive mode)
	if term.IsTerminal(int(syscall.Stdin)) {
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Error reading API key: %v\n", err)
			os.Exit(1)
		}
		cs.apiKey = string(bytePassword)
		fmt.Println()
	} else {
		// Non-interactive mode, read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			cs.apiKey = strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading API key: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Save the API key for future use
	cs.saveAPIKey()
}

func (cs *ChatSession) readInput(prompt string) (string, error) {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	// If scanner reaches EOF without error, return EOF error
	return "", fmt.Errorf("EOF")
}

func (cs *ChatSession) run() {
	// Show ASCII art first
	fmt.Println(tinfoilASCII)
	
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	
	// Show welcome message with box styling like Claude Code
	boxWidth := 60
	fmt.Printf("┌%s┐\n", strings.Repeat("─", boxWidth-2))
	
	// Helper function to create properly padded lines
	formatLine := func(text string) string {
		content := " " + text + " "
		padding := boxWidth - len(content) - 2
		return fmt.Sprintf("│%s%s│", content, strings.Repeat(" ", padding))
	}
	
	fmt.Println(formatLine("Welcome to Tinfoil Chat!"))
	fmt.Println(formatLine(""))
	fmt.Println(formatLine("/help for help, /exit to quit"))
	fmt.Println(formatLine(""))
	
	cwdText := fmt.Sprintf("cwd: %s", cwd)
	maxCwdLen := boxWidth - 6 // Account for "│ " and " │"
	if len(cwdText) > maxCwdLen {
		cwdText = cwdText[:maxCwdLen-3] + "..."
	}
	fmt.Println(formatLine(cwdText))
	
	fmt.Printf("└%s┘\n", strings.Repeat("─", boxWidth-2))
	fmt.Println()

	// Prompt for API key first
	cs.promptForAPIKey()

	if cs.currentModel == "" {
		fmt.Println("Please select a model to start chatting:")
		cs.listModels()
		fmt.Print("Enter model number (1-4): ")
		
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			numberStr := strings.TrimSpace(scanner.Text())
			if numberStr == "" {
				fmt.Print("Enter model number (1-4): ")
				continue
			}
			
			var number int
			if _, err := fmt.Sscanf(numberStr, "%d", &number); err != nil {
				fmt.Print("Please enter a valid number (1-4): ")
				continue
			}
			
			model := cs.getModelByNumber(number)
			if model == "" {
				fmt.Print("Please enter a number between 1-4: ")
				continue
			}
			
			cs.setModel(model)
			fmt.Printf("Selected model: %s\n", model)
			fmt.Println()
			break
		}
	}
	
	for {
		// Create prompt text similar to Claude Code, showing current model if set
		var promptText string
		if cs.currentModel != "" {
			// Get model alias for display
			modelAlias := cs.currentModel
			for alias, fullName := range cs.models {
				if fullName == cs.currentModel {
					modelAlias = alias
					break
				}
			}
			promptText = fmt.Sprintf("tinfoil [%s] > ", modelAlias)
		} else {
			promptText = "tinfoil > "
		}
		
		// Read input
		input, err := cs.readInput(promptText)
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("\nGoodbye!")
				break
			}
			fmt.Printf("Error reading input: %v\n", err)
			break
		}
		
		if input == "" {
			continue
		}

		// Handle commands
		if cs.handleCommand(input) {
			continue
		}

		// Send message and display response
		cs.sendMessage(input)
	}
}

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Start interactive chat mode",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		session := NewChatSession()
		session.run()
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}