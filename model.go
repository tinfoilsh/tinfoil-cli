package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// modelWrapJobView mirrors the controlplane's modelwrap job response. Only
// the fields the CLI displays or forwards are modeled.
type modelWrapJobView struct {
	JobID      string  `json:"job_id"`
	Host       string  `json:"host"`
	Repo       string  `json:"repo"`
	Commit     string  `json:"commit"`
	Status     string  `json:"status"`
	Error      string  `json:"error,omitempty"`
	RootHash   string  `json:"root_hash,omitempty"`
	Offset     int64   `json:"offset,omitempty"`
	VerityUUID string  `json:"verity_uuid,omitempty"`
	StartedAt  string  `json:"started_at,omitempty"`
	EndedAt    *string `json:"ended_at,omitempty"`
	Logs       string  `json:"logs,omitempty"`
}

var (
	modelWrapHost        string
	modelWrapCommit      string
	modelWrapHFToken     string
	modelWrapHFTokenFile string
	modelWrapWait        bool

	modelListLimit int

	modelStatusWait bool
	modelStatusLogs bool

	// modelWrapPollInterval is shortened by tests.
	modelWrapPollInterval = 10 * time.Second
)

func init() {
	rootCmd.AddCommand(modelCmd)
	modelCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	modelCmd.AddCommand(modelWrapCmd, modelListCmd, modelStatusCmd, modelDeleteCmd)

	modelWrapCmd.Flags().StringVar(&modelWrapHost, "host", "", "Host to wrap the model on (see 'tinfoil container hosts') [required]")
	modelWrapCmd.Flags().StringVar(&modelWrapCommit, "commit", "", "Hugging Face commit SHA to pin (defaults to the repo's latest commit)")
	modelWrapCmd.Flags().StringVar(&modelWrapHFToken, "hf-token", "", "Hugging Face token for gated or private repos (use --hf-token-file or stdin to avoid leaking via process listing)")
	modelWrapCmd.Flags().StringVar(&modelWrapHFTokenFile, "hf-token-file", "", "Read the Hugging Face token from this file (use - for stdin)")
	modelWrapCmd.Flags().BoolVar(&modelWrapWait, "wait", false, "Poll until the wrap job finishes and print the config block")
	_ = modelWrapCmd.MarkFlagRequired("host")

	modelListCmd.Flags().IntVar(&modelListLimit, "limit", 0, "Maximum number of jobs to list (server default 20, max 200)")

	modelStatusCmd.Flags().BoolVar(&modelStatusWait, "wait", false, "Poll until the wrap job finishes")
	modelStatusCmd.Flags().BoolVar(&modelStatusLogs, "logs", false, "Include the wrap job logs")

	silenceUsageRecursive(modelCmd)
}

var modelCmd = &cobra.Command{
	Use:          "model",
	Aliases:      []string{"models"},
	Short:        "Prepare verified model weights for containers",
	SilenceUsage: true,
}

var modelWrapCmd = &cobra.Command{
	Use:   "wrap [owner/model]",
	Short: "Wrap Hugging Face model weights into a verified artifact on a host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		token, err := readHFToken(cmd)
		if err != nil {
			return err
		}
		body := map[string]any{
			"repo": args[0],
			"host": modelWrapHost,
		}
		if modelWrapCommit != "" {
			body["commit"] = modelWrapCommit
		}
		if token != "" {
			body["hf_token"] = token
		}
		var job modelWrapJobView
		if _, err := client.do("POST", "/api/models/wrap", nil, body, &job); err != nil {
			return err
		}
		if modelWrapWait {
			finished, err := waitForModelWrap(client, job.Host, job.JobID)
			if err != nil {
				return err
			}
			job = *finished
		}
		return finishModelWrapJob(job, false, modelWrapWait)
	},
}

var modelListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List model wrap jobs in the organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var query url.Values
		if modelListLimit > 0 {
			query = url.Values{"limit": []string{strconv.Itoa(modelListLimit)}}
		}
		var list []modelWrapJobView
		if _, err := client.do("GET", "/api/models/wrap", query, nil, &list); err != nil {
			return err
		}
		return renderModelWrapJobs(list)
	},
}

var modelStatusCmd = &cobra.Command{
	Use:     "status [host] [job-id]",
	Aliases: []string{"get"},
	Short:   "Show the status of a model wrap job",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		job, err := fetchModelWrapJob(client, args[0], args[1], modelStatusWait)
		if err != nil {
			return err
		}
		return finishModelWrapJob(job, modelStatusLogs, modelStatusWait)
	},
}

var modelDeleteCmd = &cobra.Command{
	Use:     "delete [host] [job-id]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a wrap job, and its artifact once nothing references it",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		host, jobID := args[0], args[1]
		if _, err := client.do("DELETE", pathf("/api/models/wrap/%s/%s", host, jobID), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted model wrap job %s on %s\n", jobID, host)
		return nil
	},
}

func readHFToken(cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("hf-token")
	hasFile := cmd.Flags().Changed("hf-token-file")

	if hasInline && hasFile {
		return "", fmt.Errorf("--hf-token and --hf-token-file are mutually exclusive")
	}
	if hasFile {
		if modelWrapHFTokenFile == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimSpace(string(data)), nil
		}
		data, err := os.ReadFile(modelWrapHFTokenFile)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", modelWrapHFTokenFile, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return modelWrapHFToken, nil
}

func modelWrapFinished(status string) bool {
	return status != "pending" && status != "running"
}

// fetchModelWrapJob reads the job's current state, polling to a terminal
// status when wait is set.
func fetchModelWrapJob(client *cpClient, host, jobID string, wait bool) (modelWrapJobView, error) {
	if wait {
		job, err := waitForModelWrap(client, host, jobID)
		if err != nil {
			return modelWrapJobView{}, err
		}
		return *job, nil
	}
	var job modelWrapJobView
	if _, err := client.do("GET", pathf("/api/models/wrap/%s/%s", host, jobID), nil, nil, &job); err != nil {
		return modelWrapJobView{}, err
	}
	return job, nil
}

// finishModelWrapJob renders the job and reports a waited-on failure as an
// error so the command exits non-zero.
func finishModelWrapJob(job modelWrapJobView, showLogs, waited bool) error {
	if err := renderModelWrapJob(job, showLogs); err != nil {
		return err
	}
	if waited && job.Status == "failed" {
		return fmt.Errorf("model wrap failed")
	}
	return nil
}

// waitForModelWrap polls the job until it reaches a terminal status,
// reporting status changes on stderr so stdout stays machine-readable.
func waitForModelWrap(client *cpClient, host, jobID string) (*modelWrapJobView, error) {
	lastStatus := ""
	for {
		var job modelWrapJobView
		if _, err := client.do("GET", pathf("/api/models/wrap/%s/%s", host, jobID), nil, nil, &job); err != nil {
			return nil, err
		}
		if modelWrapFinished(job.Status) {
			return &job, nil
		}
		if job.Status != lastStatus {
			fmt.Fprintf(os.Stderr, "Wrap job %s: %s (large models can take several minutes)\n", jobID, job.Status)
			lastStatus = job.Status
		}
		time.Sleep(modelWrapPollInterval)
	}
}

// modelNameFromRepo derives a config-friendly model name from the
// owner/model repo, e.g. "google/gemma-4-31B-it" -> "gemma-4-31b-it".
func modelNameFromRepo(repo string) string {
	name := repo
	if idx := strings.LastIndex(repo, "/"); idx >= 0 {
		name = repo[idx+1:]
	}
	return strings.ToLower(name)
}

func modelMPK(job modelWrapJobView) string {
	return fmt.Sprintf("%s_%d_%s", job.RootHash, job.Offset, job.VerityUUID)
}

func renderModelWrapJob(job modelWrapJobView, showLogs bool) error {
	if outputFormat == "json" {
		return printJSON(job)
	}
	fmt.Printf("Job ID:   %s\n", job.JobID)
	fmt.Printf("Host:     %s\n", job.Host)
	fmt.Printf("Repo:     %s\n", job.Repo)
	if job.Commit != "" {
		fmt.Printf("Commit:   %s\n", job.Commit)
	}
	fmt.Printf("Status:   %s\n", job.Status)
	if job.StartedAt != "" {
		fmt.Printf("Started:  %s\n", job.StartedAt)
	}
	if job.EndedAt != nil {
		fmt.Printf("Ended:    %s\n", *job.EndedAt)
	}
	if job.Error != "" {
		fmt.Printf("Error:    %s\n", job.Error)
	}

	switch {
	case job.Status == "complete" && job.RootHash != "":
		fmt.Printf("\nAdd this to tinfoil-config.yml:\n\n")
		fmt.Printf("models:\n")
		fmt.Printf("  - name: %q\n", modelNameFromRepo(job.Repo))
		fmt.Printf("    repo: %q\n", job.Repo+"@"+job.Commit)
		fmt.Printf("    mpk: %q\n", modelMPK(job))
		fmt.Printf("\nThe verified weights are mounted in the enclave at:\n")
		fmt.Printf("  /tinfoil/mpk/mpk-%s\n", job.RootHash)
	case !modelWrapFinished(job.Status):
		fmt.Printf("\nPoll with `tinfoil model status %s %s`.\n", job.Host, job.JobID)
	}

	if showLogs && job.Logs != "" {
		fmt.Printf("\nLogs:\n%s\n", strings.TrimRight(job.Logs, "\n"))
	}
	return nil
}

func renderModelWrapJobs(list []modelWrapJobView) error {
	if outputFormat == "json" {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No model wrap jobs.")
		return nil
	}
	fmt.Printf("%-16s  %-12s  %-32s  %-12s  %-8s  %s\n", "JOB ID", "HOST", "REPO", "COMMIT", "STATUS", "STARTED")
	for _, job := range list {
		commit := job.Commit
		if commit == "" {
			commit = "-"
		}
		fmt.Printf("%-16s  %-12s  %-32s  %-12s  %-8s  %s\n",
			job.JobID, truncate(job.Host, 12), truncate(job.Repo, 32),
			truncate(commit, 12), job.Status, truncate(job.StartedAt, 19),
		)
	}
	return nil
}
