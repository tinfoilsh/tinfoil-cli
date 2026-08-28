package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const maxConfigFileBytes = 20 * 1024 * 1024

type repoConfigResponse struct {
	Success          bool            `json:"success"`
	Config           json.RawMessage `json:"config"`
	Raw              string          `json:"raw"`
	Exists           bool            `json:"exists"`
	FileSHA          string          `json:"file_sha"`
	DefaultBranch    string          `json:"default_branch"`
	HasBuildWorkflow bool            `json:"has_build_workflow"`
}

type repoConfigPRResponse struct {
	Success  bool   `json:"success"`
	PRURL    string `json:"pr_url"`
	PRNumber int    `json:"pr_number"`
	Branch   string `json:"branch"`
}

type repoPullResponse struct {
	Success  bool   `json:"success"`
	PRNumber int    `json:"pr_number"`
	State    string `json:"state"`
	Merged   bool   `json:"merged"`
	PRURL    string `json:"pr_url"`
}

type repoBuildInfoResponse struct {
	Success              bool   `json:"success"`
	LatestTag            string `json:"latest_tag"`
	SuggestedNextVersion string `json:"suggested_next_version"`
}

type repoBuildResponse struct {
	Success        bool   `json:"success"`
	Version        string `json:"version"`
	WorkflowRunURL string `json:"workflow_run_url"`
}

var (
	repoConfigRaw  bool
	repoConfigFile string
	repoPRBody     string
	repoVersion    string
)

func init() {
	rootCmd.AddCommand(repoCmd)
	repoCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	repoCmd.AddCommand(repoConfigCmd, repoPRCmd, repoBuildCmd)
	repoConfigCmd.AddCommand(repoConfigGetCmd, repoConfigPRCmd)
	repoPRCmd.AddCommand(repoPRStatusCmd)
	repoBuildCmd.AddCommand(repoBuildInfoCmd, repoBuildRunCmd)

	repoConfigGetCmd.Flags().BoolVar(&repoConfigRaw, "raw", false, "Print only the raw tinfoil-config.yml")
	repoConfigPRCmd.Flags().StringVar(&repoConfigFile, "file", "", "Path to tinfoil-config.yml; use - for stdin")
	repoConfigPRCmd.Flags().StringVar(&repoPRBody, "body", "", "Optional pull request description")
	repoBuildRunCmd.Flags().StringVar(&repoVersion, "version", "", "Release version (for example v1.2.3)")
	_ = repoConfigPRCmd.MarkFlagRequired("file")
	_ = repoBuildRunCmd.MarkFlagRequired("version")

	silenceUsageRecursive(repoCmd)
}

var repoCmd = &cobra.Command{
	Use:          "repo",
	Aliases:      []string{"repository", "repositories"},
	Short:        "Manage container config repositories",
	SilenceUsage: true,
}

var repoConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Read or propose changes to tinfoil-config.yml",
}

var repoConfigGetCmd = &cobra.Command{
	Use:   "get [owner/repo]",
	Short: "Fetch tinfoil-config.yml through the installed GitHub App",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if repoConfigRaw && outputFormat == "json" {
			return fmt.Errorf("--raw and --output json cannot be used together")
		}
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		var response repoConfigResponse
		if _, err := client.do("GET", repository.apiPath()+"/config", nil, nil, &response); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(response)
		}
		if repoConfigRaw {
			fmt.Print(response.Raw)
			return nil
		}
		fmt.Printf("Repository:       %s/%s\n", repository.owner, repository.name)
		fmt.Printf("Default branch:   %s\n", response.DefaultBranch)
		fmt.Printf("Config exists:    %v\n", response.Exists)
		fmt.Printf("Release workflow: %v\n", response.HasBuildWorkflow)
		if response.Raw != "" {
			fmt.Printf("\n%s", response.Raw)
		}
		return nil
	},
}

var repoConfigPRCmd = &cobra.Command{
	Use:   "pr [owner/repo]",
	Short: "Open a pull request with a local tinfoil-config.yml",
	Long:  "Open a pull request through the installed GitHub App. Do not put secret values in the config: verification metadata is exposed by the enclave endpoint even when the repository is private.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		raw, err := readConfigInput(repoConfigFile)
		if err != nil {
			return err
		}
		body := map[string]any{"raw": raw}
		if repoPRBody != "" {
			body["pr_body"] = repoPRBody
		}
		var response repoConfigPRResponse
		if _, err := client.do("POST", repository.apiPath()+"/config/pr", nil, body, &response); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(response)
		}
		fmt.Printf("Opened pull request #%d: %s\n", response.PRNumber, response.PRURL)
		fmt.Printf("Branch: %s\n", response.Branch)
		return nil
	},
}

var repoPRCmd = &cobra.Command{
	Use:   "pr",
	Short: "Inspect config pull requests",
}

var repoPRStatusCmd = &cobra.Command{
	Use:   "status [owner/repo] [number]",
	Short: "Show the status of a config pull request",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := strconv.Atoi(args[1])
		if err != nil || number <= 0 {
			return fmt.Errorf("pull request number must be a positive integer")
		}
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		var response repoPullResponse
		path := repository.apiPath() + "/pulls/" + strconv.Itoa(number)
		if _, err := client.do("GET", path, nil, nil, &response); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(response)
		}
		fmt.Printf("Pull request: #%d\n", response.PRNumber)
		fmt.Printf("State:        %s\n", response.State)
		fmt.Printf("Merged:       %v\n", response.Merged)
		fmt.Printf("URL:          %s\n", response.PRURL)
		return nil
	},
}

var repoBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Inspect or trigger the Tinfoil Release workflow",
}

var repoBuildInfoCmd = &cobra.Command{
	Use:   "info [owner/repo]",
	Short: "Show the latest tag and suggested next version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		var response repoBuildInfoResponse
		if _, err := client.do("GET", repository.apiPath()+"/build/info", nil, nil, &response); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(response)
		}
		latest := response.LatestTag
		if latest == "" {
			latest = "-"
		}
		fmt.Printf("Latest tag:             %s\n", latest)
		fmt.Printf("Suggested next version: %s\n", response.SuggestedNextVersion)
		return nil
	},
}

var repoBuildRunCmd = &cobra.Command{
	Use:   "run [owner/repo]",
	Short: "Trigger the Tinfoil Release workflow",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository, client, err := repositoryCommand(args[0])
		if err != nil {
			return err
		}
		var response repoBuildResponse
		body := map[string]string{"version": repoVersion}
		if _, err := client.do("POST", repository.apiPath()+"/build", nil, body, &response); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(response)
		}
		fmt.Printf("Triggered release %s\n", response.Version)
		fmt.Printf("GitHub Actions: %s\n", response.WorkflowRunURL)
		return nil
	},
}

type repositoryRef struct {
	owner string
	name  string
}

func parseRepository(value string) (repositoryRef, error) {
	owner, name, ok := strings.Cut(strings.TrimSpace(value), "/")
	if !ok || !validRepositorySegment(owner) || !validRepositorySegment(name) || strings.Contains(name, "/") {
		return repositoryRef{}, fmt.Errorf("repository must be in owner/repo format")
	}
	return repositoryRef{owner: owner, name: name}, nil
}

func validRepositorySegment(value string) bool {
	return value != "" && value != "." && value != ".."
}

func (r repositoryRef) apiPath() string {
	return pathf("/api/github/repos/%s/%s", r.owner, r.name)
}

func repositoryCommand(value string) (repositoryRef, *cpClient, error) {
	repository, err := parseRepository(value)
	if err != nil {
		return repositoryRef{}, nil, err
	}
	client, err := authedClient()
	if err != nil {
		return repositoryRef{}, nil, err
	}
	return repository, client, nil
}

func readConfigInput(path string) (string, error) {
	var (
		reader io.Reader
		file   *os.File
		err    error
	)
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err = os.Open(path)
		if err != nil {
			return "", fmt.Errorf("opening config file: %w", err)
		}
		defer file.Close()
		reader = file
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxConfigFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading config file: %w", err)
	}
	if len(data) > maxConfigFileBytes {
		return "", fmt.Errorf("config file exceeds %d bytes", maxConfigFileBytes)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", fmt.Errorf("config file is empty")
	}
	return string(data), nil
}
