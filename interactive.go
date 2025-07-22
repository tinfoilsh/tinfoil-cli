package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
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

var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
	gray    = color.New(color.FgHiBlack).SprintFunc()
	bold    = color.New(color.Bold).SprintFunc()
	italic  = color.New(color.Italic).SprintFunc()
)

type ChatSession struct {
	messages     []ChatMessage
	currentModel string
	models       map[string]string
	apiKey       string
	termWidth    int
}

func NewChatSession() *ChatSession {
	models, err := loadDefaultConfig()
	if err != nil {
		models = make(map[string]string)
	}

	width, _, _ := term.GetSize(int(os.Stdout.Fd()))
	if width == 0 {
		width = 80
	}

	return &ChatSession{
		messages:  []ChatMessage{{Role: "system", Content: "You are a helpful assistant."}},
		models:    models,
		termWidth: width,
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
	fmt.Println()
	fmt.Println(bold(cyan("Available Models")))
	fmt.Println(strings.Repeat("─", 40))

	chatModels := []struct {
		alias        string
		friendlyName string
	}{
		{"llama", "Llama 3.3 70B"},
		{"deepseek", "DeepSeek R1 70B"},
		{"mistral", "Mistral Small 3.1 24B"},
		{"qwen", "Qwen 2.5 72B"},
	}

	for i, model := range chatModels {
		if resolvedModel, exists := cs.models[model.alias]; exists {
			isCurrent := cs.currentModel == resolvedModel || cs.currentModel == model.alias
			if isCurrent {
				fmt.Printf("  %s. %s - %s %s\n",
					bold(cyan(fmt.Sprintf("%d", i+1))),
					yellow(model.alias),
					model.friendlyName,
					green("[current]"))
			} else {
				fmt.Printf("  %s. %s - %s\n",
					cyan(fmt.Sprintf("%d", i+1)),
					white(model.alias),
					gray(model.friendlyName))
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
	// Debug: print the input to see what we're getting
	// fmt.Printf("DEBUG: Got command input: %q (length: %d)\n", input, len(input))

	switch {
	case input == "/models":
		cs.listModels()
		return true
	case strings.HasPrefix(input, "/model "):
		numberStr := strings.TrimSpace(strings.TrimPrefix(input, "/model "))
		if numberStr == "" {
			fmt.Println(red("Usage: /model <number>"))
			fmt.Println(gray("Use /models to see available models"))
			return true
		}

		var number int
		if _, err := fmt.Sscanf(numberStr, "%d", &number); err != nil {
			fmt.Println(red("Please enter a valid number"))
			return true
		}

		model := cs.getModelByNumber(number)
		if model == "" {
			fmt.Println(red("Invalid model number"))
			return true
		}

		cs.setModel(model)
		fmt.Printf("\n%s Switched to %s\n\n", green("✓"), bold(yellow(model)))
		return true
	case input == "/help":
		cs.showHelp()
		return true
	case input == "/clear":
		cs.messages = []ChatMessage{{Role: "system", Content: "You are a helpful assistant."}}
		clearScreen()
		fmt.Printf("\n%s Chat history cleared!\n\n", green("✓"))
		return true
	case input == "/exit" || input == "/quit" || input == "\\exit" || input == "\\quit" || input == "exit" || input == "quit":
		fmt.Printf("\n%s\n", yellow("Goodbye!"))
		os.Exit(0)
		return true
	}
	return false
}

func (cs *ChatSession) showHelp() {
	fmt.Println()
	fmt.Println(bold(cyan("Available Commands")))
	fmt.Println(strings.Repeat("─", 50))

	commands := []struct {
		cmd         string
		description string
	}{
		{"/models", "List available models"},
		{"/model <number>", "Switch to a specific model"},
		{"/clear", "Clear chat history"},
		{"/help", "Show this help message"},
		{"/exit, /quit", "Exit the chat"},
	}

	for _, cmd := range commands {
		fmt.Printf("  %s - %s\n",
			yellow(cmd.cmd),
			gray(cmd.description))
	}

	fmt.Println()
	fmt.Println(italic(gray("Just type your message and press Enter to chat!")))
	fmt.Println()
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func wrapText(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

func (cs *ChatSession) displayMessage(role, content string, timestamp time.Time) {
	timeStr := timestamp.Format("15:04")
	maxWidth := cs.termWidth - 10
	if maxWidth < 40 {
		maxWidth = 40
	}

	if role == "user" {
		fmt.Println()
		fmt.Printf("%s %s\n", gray(timeStr), bold(cyan("You")))

		lines := wrapText(content, maxWidth)
		for _, line := range lines {
			fmt.Printf("%s\n", white(line))
		}
	} else {
		fmt.Println()
		modelName := "Assistant"
		if cs.currentModel != "" {
			// Extract just the model name from the full model string
			parts := strings.Split(cs.currentModel, "/")
			if len(parts) > 0 {
				modelName = parts[len(parts)-1]
			}
		}
		fmt.Printf("%s %s\n", gray(timeStr), bold(magenta(modelName)))
	}
}

func (cs *ChatSession) showTypingIndicator() {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan bool)

	go func() {
		i := 0
		for {
			select {
			case <-done:
				fmt.Print("\r\033[K")
				return
			default:
				fmt.Printf("\r  %s %s", cyan(frames[i%len(frames)]), gray("Thinking..."))
				time.Sleep(80 * time.Millisecond)
				i++
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	done <- true
	close(done)
}

func (cs *ChatSession) sendMessage(content string) {
	if cs.currentModel == "" {
		fmt.Printf("\n%s No model selected. Use %s to see available models.\n",
			red("Error:"),
			yellow("/models"))
		return
	}

	cs.addMessage("user", content)

	if enclaveHost == "" || repo == "" {
		enclaveHost = PROXY_ENCLAVE
		repo = PROXY_REPO
	}

	modelName = cs.currentModel
	apiKey = cs.apiKey

	cs.showTypingIndicator()

	timestamp := time.Now()

	reqPayload := ChatRequest{
		Model:    cs.currentModel,
		Messages: cs.messages,
		Stream:   true,
	}

	cs.displayMessage("assistant", "", timestamp)

	response, err := handleChatInferenceWithPayload(reqPayload)
	if err != nil {
		fmt.Printf("\n\033[31mError: %v\033[0m\n", err)
		return
	}
	if response != "" {
		cs.addMessage("assistant", response)
	}
	fmt.Println()
	fmt.Println()
}


func (cs *ChatSession) loadEnvFile() {
	// Try to load .env file from current directory
	envFile := ".env"
	data, err := os.ReadFile(envFile)
	if err != nil {
		// Try home directory
		homeDir, _ := os.UserHomeDir()
		if homeDir != "" {
			envFile = filepath.Join(homeDir, ".tinfoil.env")
			data, err = os.ReadFile(envFile)
			if err != nil {
				return
			}
		} else {
			return
		}
	}

	// Parse .env file
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "TINFOIL_API_KEY" {
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			value = strings.Trim(value, `"'`)
			if value != "" {
				cs.apiKey = value
				fmt.Printf("%s Using API key from .env file...\n", green("✓"))
				return
			}
		}
	}
}

func (cs *ChatSession) promptForAPIKey() {
	// First check environment variable
	if envKey := os.Getenv("TINFOIL_API_KEY"); envKey != "" {
		cs.apiKey = envKey
		fmt.Printf("%s Using API key from environment variable...\n", green("✓"))
		return
	}

	// Then check .env file
	cs.loadEnvFile()
	if cs.apiKey != "" {
		return
	}

	fmt.Print(yellow("Enter your API key: "))

	if term.IsTerminal(int(syscall.Stdin)) {
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("\n%s Error reading API key: %v\n", red("Error:"), err)
			os.Exit(1)
		}
		cs.apiKey = string(bytePassword)
		fmt.Println()
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			cs.apiKey = strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("%s Error reading API key: %v\n", red("Error:"), err)
			os.Exit(1)
		}
	}

	fmt.Printf("%s API key loaded successfully!\n", green("✓"))
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
	return "", fmt.Errorf("EOF")
}

func stripAnsiCodes(s string) string {
	var result strings.Builder
	ansi := false

	for _, ch := range s {
		if ch == '\033' {
			ansi = true
		} else if ansi && ch == 'm' {
			ansi = false
		} else if !ansi {
			result.WriteRune(ch)
		}
	}

	return result.String()
}

func drawBox(title string, lines []string, width int) {
	titleDisplay := fmt.Sprintf(" %s ", bold(cyan(title)))
	titleLen := len(stripAnsiCodes(titleDisplay))

	leftPadding := 2
	rightPadding := width - titleLen - leftPadding - 2
	if rightPadding < 0 {
		rightPadding = 0
	}

	fmt.Printf("╭%s%s%s╮\n",
		strings.Repeat("─", leftPadding),
		titleDisplay,
		strings.Repeat("─", rightPadding))

	for _, line := range lines {
		displayLine := fmt.Sprintf("  %s", line)
		actualLen := len(stripAnsiCodes(displayLine))
		padding := width - actualLen - 2
		if padding < 0 {
			padding = 0
		}
		fmt.Printf("│%s%s│\n", displayLine, strings.Repeat(" ", padding))
	}

	fmt.Printf("╰%s╯\n", strings.Repeat("─", width-2))
}

func (cs *ChatSession) run() {
	clearScreen()

	fmt.Println(cyan(tinfoilASCII))
	fmt.Println()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	if len(cwd) > 45 {
		cwd = "..." + cwd[len(cwd)-42:]
	}

	width := 60
	content := []string{
		fmt.Sprintf("%s to %s", gray("Welcome"), bold("Tinfoil Chat!")),
		"",
		fmt.Sprintf("Type %s for commands", yellow("/help")),
		fmt.Sprintf("Type %s to quit", yellow("/exit")),
		"",
		fmt.Sprintf("%s %s", gray("cwd:"), italic(blue(cwd))),
	}

	drawBox("Tinfoil Chat v0.1", content, width)
	fmt.Println()

	cs.promptForAPIKey()
	fmt.Println()

	if cs.currentModel == "" {
		fmt.Println(bold(cyan("Please select a model to start chatting:")))
		cs.listModels()

		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print(yellow("Select model (1-4): "))

			if !scanner.Scan() {
				break
			}

			numberStr := strings.TrimSpace(scanner.Text())
			if numberStr == "" {
				continue
			}

			var number int
			if _, err := fmt.Sscanf(numberStr, "%d", &number); err != nil {
				fmt.Printf("%s Please enter a valid number\n", red("Error:"))
				continue
			}

			model := cs.getModelByNumber(number)
			if model == "" {
				fmt.Printf("%s Please enter a number between 1-4\n", red("Error:"))
				continue
			}

			cs.setModel(model)
			fmt.Printf("\n%s Selected %s\n", green("✓"), bold(yellow(model)))
			fmt.Println()
			break
		}
	}

	fmt.Println(gray(strings.Repeat("─", cs.termWidth)))
	fmt.Println()

	for {
		promptText := fmt.Sprintf("%s ", cyan(">"))

		input, err := cs.readInput(promptText)
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Printf("\n%s\n", yellow("Goodbye!"))
				break
			}
			fmt.Printf("%s Error reading input: %v\n", red("Error:"), err)
			break
		}

		if input == "" {
			continue
		}

		if cs.handleCommand(input) {
			continue
		}

		cs.sendMessage(input)
	}
}

var interactiveCmd = &cobra.Command{
	Use:    "interactive",
	Short:  "Start interactive chat mode",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		session := NewChatSession()
		session.run()
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}
