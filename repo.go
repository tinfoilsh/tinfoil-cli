package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
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
	Success              bool          `json:"success"`
	LatestTag            string        `json:"latest_tag"`
	SuggestedNextVersion string        `json:"suggested_next_version"`
	LatestReleaseTag     string        `json:"latest_release_tag"`
	HasNewCommits        bool          `json:"has_new_commits"`
	Releases             []repoRelease `json:"releases"`
}

type repoRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Prerelease  bool   `json:"prerelease"`
}

type repoBuildStatusResponse struct {
	Success bool   `json:"success"`
	Version string `json:"version"`
	Run     *struct {
		ID           int64  `json:"id"`
		Status       string `json:"status"`
		Conclusion   string `json:"conclusion"`
		HTMLURL      string `json:"html_url"`
		DisplayTitle string `json:"display_title"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
	} `json:"run"`
}

type repoBuildResponse struct {
	Success        bool   `json:"success"`
	Version        string `json:"version"`
	WorkflowRunURL string `json:"workflow_run_url"`
}

func newRepoCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoCmd := &cobra.Command{
		Use:     "repo",
		Aliases: []string{"repository", "repositories"},
		Short:   "Manage container config repositories",
	}
	repoCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	repoCmd.AddCommand(newRepoConfigCommand(newClient, outputOpts), newRepoPRCommand(newClient, outputOpts), newRepoBuildCommand(newClient, outputOpts))
	repoCmd.AddCommand(newRepoSecretCommand(newClient, outputOpts))
	return repoCmd
}

func newRepoConfigCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoConfigCmd := &cobra.Command{
		Use:   "config",
		Short: "Read or propose changes to tinfoil-config.yml",
	}
	repoConfigCmd.AddCommand(newRepoConfigGetCommand(newClient, outputOpts, &repoConfigGetOptions{}), newRepoConfigPRCommand(newClient, outputOpts, &repoConfigPROptions{}))
	return repoConfigCmd
}

func newRepoConfigGetCommand(newClient authenticatedClientFactory, outputOpts *outputOptions, repoConfigGetOpts *repoConfigGetOptions) *cobra.Command {
	repoConfigGetCmd := &cobra.Command{
		Use:   "get [owner/repo]",
		Short: "Fetch a repo's tinfoil-config.yml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if repoConfigGetOpts.repoConfigRaw && outputOpts.outputFormat == "json" {
				return fmt.Errorf("--raw and --output json cannot be used together")
			}
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			var response repoConfigResponse
			if _, err := client.do("GET", repository.apiPath()+"/config", nil, nil, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			if repoConfigGetOpts.repoConfigRaw {
				fmt.Fprint(commandStreams(cmd).out, response.Raw)
				return nil
			}
			fmt.Fprintf(commandStreams(cmd).out, "Repository:       %s/%s\n", repository.owner, repository.name)
			fmt.Fprintf(commandStreams(cmd).out, "Default branch:   %s\n", response.DefaultBranch)
			fmt.Fprintf(commandStreams(cmd).out, "Config exists:    %v\n", response.Exists)
			fmt.Fprintf(commandStreams(cmd).out, "Release workflow: %v\n", response.HasBuildWorkflow)
			if response.Raw != "" {
				fmt.Fprintf(commandStreams(cmd).out, "\n%s", response.Raw)
			}
			return nil
		},
	}
	repoConfigGetCmd.Flags().BoolVar(&repoConfigGetOpts.repoConfigRaw, "raw", false, "Print only the raw tinfoil-config.yml")
	return repoConfigGetCmd
}

func newRepoConfigPRCommand(newClient authenticatedClientFactory, outputOpts *outputOptions, repoConfigPROpts *repoConfigPROptions) *cobra.Command {
	repoConfigPRCmd := &cobra.Command{
		Use:   "pr [owner/repo]",
		Short: "Open a pull request with a local tinfoil-config.yml",
		Long:  "The repository is public, so keep secret values out of the config.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			raw, err := readConfigInput(commandStreams(cmd), repoConfigPROpts.repoConfigFile)
			if err != nil {
				return err
			}
			body := map[string]any{"raw": raw}
			if repoConfigPROpts.repoPRBody != "" {
				body["pr_body"] = repoConfigPROpts.repoPRBody
			}
			var response repoConfigPRResponse
			if _, err := client.do("POST", repository.apiPath()+"/config/pr", nil, body, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			fmt.Fprintf(commandStreams(cmd).out, "Opened pull request #%d: %s\n", response.PRNumber, response.PRURL)
			fmt.Fprintf(commandStreams(cmd).out, "Branch: %s\n", response.Branch)
			fmt.Fprintln(commandStreams(cmd).out, "Merge this pull request before publishing a release; opening it does not change the default branch.")
			fmt.Fprintf(commandStreams(cmd).out, "Check merge status: tinfoil repo pr status %s/%s %d\n", repository.owner, repository.name, response.PRNumber)
			return nil
		},
	}
	repoConfigPRCmd.Flags().StringVar(&repoConfigPROpts.repoConfigFile, "file", "", "Path to tinfoil-config.yml; use - for stdin")
	repoConfigPRCmd.Flags().StringVar(&repoConfigPROpts.repoPRBody, "body", "", "Optional pull request description")
	_ = repoConfigPRCmd.MarkFlagRequired("file")
	return repoConfigPRCmd
}

func newRepoPRCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoPRCmd := &cobra.Command{
		Use:   "pr",
		Short: "Inspect config pull requests",
	}
	repoPRCmd.AddCommand(newRepoPRStatusCommand(newClient, outputOpts))
	return repoPRCmd
}

func newRepoPRStatusCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoPRStatusCmd := &cobra.Command{
		Use:   "status [owner/repo] [number]",
		Short: "Show the status of a config pull request",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			number, err := strconv.Atoi(args[1])
			if err != nil || number <= 0 {
				return fmt.Errorf("pull request number must be a positive integer")
			}
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			var response repoPullResponse
			path := repository.apiPath() + "/pulls/" + strconv.Itoa(number)
			if _, err := client.do("GET", path, nil, nil, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			fmt.Fprintf(commandStreams(cmd).out, "Pull request: #%d\n", response.PRNumber)
			fmt.Fprintf(commandStreams(cmd).out, "State:        %s\n", response.State)
			fmt.Fprintf(commandStreams(cmd).out, "Merged:       %v\n", response.Merged)
			fmt.Fprintf(commandStreams(cmd).out, "URL:          %s\n", response.PRURL)
			return nil
		},
	}

	return repoPRStatusCmd
}

func newRepoBuildCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoBuildCmd := &cobra.Command{
		Use:   "build",
		Short: "Inspect or trigger the Tinfoil Release workflow",
	}
	repoBuildCmd.AddCommand(newRepoBuildInfoCommand(newClient, outputOpts), newRepoBuildRunCommand(newClient, outputOpts, &repoBuildRunOptions{}), newRepoBuildStatusCommand(newClient, outputOpts, &repoBuildStatusOptions{}))
	return repoBuildCmd
}

func newRepoBuildInfoCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	repoBuildInfoCmd := &cobra.Command{
		Use:   "info [owner/repo]",
		Short: "Show tags, published releases, and the suggested next version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			var response repoBuildInfoResponse
			if _, err := client.do("GET", repository.apiPath()+"/build/info", nil, nil, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			latest := response.LatestTag
			if latest == "" {
				latest = "-"
			}
			fmt.Fprintf(commandStreams(cmd).out, "Latest tag:             %s\n", latest)
			fmt.Fprintf(commandStreams(cmd).out, "Suggested next version: %s\n", response.SuggestedNextVersion)
			if response.LatestReleaseTag == "" {
				fmt.Fprintln(commandStreams(cmd).out, "Latest GitHub release:  none published")
			} else {
				fmt.Fprintf(commandStreams(cmd).out, "Latest GitHub release:  %s\n", response.LatestReleaseTag)
			}
			for _, release := range response.Releases {
				fmt.Fprintf(commandStreams(cmd).out, "Published release:     %s at %s (prerelease=%t) %s\n", release.TagName, release.PublishedAt, release.Prerelease, release.HTMLURL)
			}
			fmt.Fprintln(commandStreams(cmd).out, "A tag alone is not deployable. Wait for both Tinfoil Release and Build & Publish to succeed and for the same tag's release to be published.")
			return nil
		},
	}

	return repoBuildInfoCmd
}

func newRepoBuildRunCommand(newClient authenticatedClientFactory, outputOpts *outputOptions, repoBuildRunOpts *repoBuildRunOptions) *cobra.Command {
	repoBuildRunCmd := &cobra.Command{
		Use:   "run [owner/repo]",
		Short: "Trigger the Tinfoil Release workflow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			var response repoBuildResponse
			body := map[string]string{"version": repoBuildRunOpts.repoVersion}
			if _, err := client.do("POST", repository.apiPath()+"/build", nil, body, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			fmt.Fprintf(commandStreams(cmd).out, "Queued release %s; not yet deployable.\n", response.Version)
			fmt.Fprintf(commandStreams(cmd).out, "GitHub Actions: %s\n", response.WorkflowRunURL)
			fmt.Fprintf(commandStreams(cmd).out, "All workflows (including Build & Publish): https://github.com/%s/%s/actions\n", repository.owner, repository.name)
			fmt.Fprintf(commandStreams(cmd).out, "Check status (read-only): tinfoil repo build status %s/%s --version %s\n", repository.owner, repository.name, shellQuote(response.Version))
			fmt.Fprintln(commandStreams(cmd).out, "Wait for both Tinfoil Release and Build & Publish to succeed, then confirm the same tag is published with repo build info before creating a container.")
			return nil
		},
	}
	repoBuildRunCmd.Flags().StringVar(&repoBuildRunOpts.repoVersion, "version", "", "Release version (for example v1.2.3)")
	_ = repoBuildRunCmd.MarkFlagRequired("version")
	return repoBuildRunCmd
}

func newRepoBuildStatusCommand(newClient authenticatedClientFactory, outputOpts *outputOptions, repoBuildStatusOpts *repoBuildStatusOptions) *cobra.Command {
	repoBuildStatusCmd := &cobra.Command{
		Use:   "status [owner/repo]",
		Short: "Check a queued release workflow without starting a build",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, client, err := repositoryCommand(commandStreams(cmd), newClient, args[0])
			if err != nil {
				return err
			}
			var response repoBuildStatusResponse
			if _, err := client.do("GET", repository.apiPath()+"/build/status", url.Values{"version": {repoBuildStatusOpts.repoStatusVersion}}, nil, &response); err != nil {
				return err
			}
			if outputOpts.outputFormat == "json" {
				return printJSON(commandStreams(cmd), response)
			}
			if response.Run == nil {
				fmt.Fprintf(commandStreams(cmd).out, "Release %s: waiting for workflow visibility; not yet deployable.\n", response.Version)
			} else {
				fmt.Fprintf(commandStreams(cmd).out, "Release %s: %s (conclusion: %s)\nGitHub Actions: %s\n", response.Version, response.Run.Status, response.Run.Conclusion, response.Run.HTMLURL)
			}
			fmt.Fprintf(commandStreams(cmd).out, "Confirm Build & Publish also succeeds, then check the published tag: tinfoil repo build info %s/%s\n", repository.owner, repository.name)
			fmt.Fprintf(commandStreams(cmd).out, "All workflows: https://github.com/%s/%s/actions\n", repository.owner, repository.name)
			return nil
		},
	}
	repoBuildStatusCmd.Flags().StringVar(&repoBuildStatusOpts.repoStatusVersion, "version", "", "Dispatched release version [required]")
	_ = repoBuildStatusCmd.MarkFlagRequired("version")
	return repoBuildStatusCmd
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

func repositoryCommand(streams commandIO, newClient authenticatedClientFactory, value string) (repositoryRef, *cpClient, error) {
	repository, err := parseRepository(value)
	if err != nil {
		return repositoryRef{}, nil, err
	}
	client, err := newClient(streams)
	if err != nil {
		return repositoryRef{}, nil, err
	}
	return repository, client, nil
}

func readConfigInput(streams commandIO, path string) (string, error) {
	var (
		reader io.Reader
		file   *os.File
		err    error
	)
	if path == "-" {
		reader = streams.in
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
