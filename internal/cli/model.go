package cli

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

const defaultModelWrapPollInterval = 10 * time.Second

func newModelCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	modelCmd := &cobra.Command{
		Use:     "model",
		Aliases: []string{"models"},
		Short:   "Prepare verified model weights for containers",
	}
	modelCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	modelCmd.AddCommand(newModelWrapCommand(pollingOpts, newClient, &modelWrapOptions{}, outputOpts), newModelUpdateCommand(pollingOpts, newClient, &modelUpdateOptions{}, outputOpts), newModelListCommand(newClient, &modelListOptions{}, outputOpts), newModelStatusCommand(pollingOpts, newClient, &modelStatusOptions{}, outputOpts), newModelDeleteCommand(newClient))
	return modelCmd
}

func newModelWrapCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, modelWrapOpts *modelWrapOptions, outputOpts *outputOptions) *cobra.Command {
	modelWrapCmd := &cobra.Command{
		Use:   "wrap [owner/model]",
		Short: "Wrap Hugging Face weights into a verified artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			token, err := readHFToken(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{
				"repo": args[0],
				"host": modelWrapOpts.modelWrapHost,
			}
			if modelWrapOpts.modelWrapCommit != "" {
				body["commit"] = modelWrapOpts.modelWrapCommit
			}
			if token != "" {
				body["hf_token"] = token
			}
			return runModelWrapJob(pollingOpts, commandStreams(cmd), outputOpts, client, body, modelWrapOpts.modelWrapWait, nil)
		},
	}
	modelWrapCmd.Flags().StringVar(&modelWrapOpts.modelWrapHost, "host", "", "Host to wrap the model on (see 'tinfoil container hosts') [required]")
	modelWrapCmd.Flags().StringVar(&modelWrapOpts.modelWrapCommit, "commit", "", "Hugging Face commit SHA to pin (defaults to the repo's latest commit)")
	modelWrapCmd.Flags().StringVar(&modelWrapOpts.modelWrapHFToken, "hf-token", "", "Hugging Face token (visible in ps; prefer --hf-token-file or stdin)")
	modelWrapCmd.Flags().StringVar(&modelWrapOpts.modelWrapHFTokenFile, "hf-token-file", "", "Read the Hugging Face token from this file (use - for stdin)")
	modelWrapCmd.Flags().BoolVar(&modelWrapOpts.modelWrapWait, "wait", false, "Poll until the wrap job finishes and print the config block")
	_ = modelWrapCmd.MarkFlagRequired("host")
	return modelWrapCmd
}

func newModelUpdateCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, modelUpdateOpts *modelUpdateOptions, outputOpts *outputOptions) *cobra.Command {
	modelUpdateCmd := &cobra.Command{
		Use:   "update [owner/model]",
		Short: "Wrap a newer revision of a previously wrapped model",
		Long: `The old artifact is kept. Point tinfoil-config.yml at the new repo/mpk values,
release, then delete the old wrap job.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			token, err := readHFToken(cmd)
			if err != nil {
				return err
			}
			repo := args[0]

			previous, err := latestCompleteModelWrap(client, repo, modelUpdateOpts.modelUpdateHost)
			if err != nil {
				return err
			}
			if previous == nil {
				return fmt.Errorf("no completed wrap job for %s on %s among the %d most recent jobs — start one with `tinfoil model wrap`", repo, modelUpdateOpts.modelUpdateHost, modelWrapSearchWindow)
			}

			target := modelUpdateOpts.modelUpdateCommit
			if target == "" {
				if target, err = resolveLatestHFCommit(client, repo, token); err != nil {
					return err
				}
			}
			if target == previous.Commit {
				if outputOpts.outputFormat == "json" {
					return printJSON(commandStreams(cmd), previous)
				}
				fmt.Fprintf(commandStreams(cmd).out, "%s on %s is already at commit %s (job %s).\n", repo, previous.Host, target, previous.JobID)
				return nil
			}

			body := map[string]any{
				"repo":   repo,
				"host":   modelUpdateOpts.modelUpdateHost,
				"commit": target,
			}
			if token != "" {
				body["hf_token"] = token
			}
			if outputOpts.outputFormat != "json" {
				fmt.Fprintf(commandStreams(cmd).out, "Updating %s on %s: %s -> %s\n\n", repo, previous.Host, shortCommit(previous.Commit), shortCommit(target))
			}
			return runModelWrapJob(pollingOpts, commandStreams(cmd), outputOpts, client, body, modelUpdateOpts.modelUpdateWait, func(job modelWrapJobView) {
				if outputOpts.outputFormat != "json" && job.Status == "complete" {
					fmt.Fprintf(commandStreams(cmd).out, "\nOnce the new config is released and deployed, reclaim the previous artifact with:\n  tinfoil model delete %s %s\n", previous.Host, previous.JobID)
				}
			})
		},
	}
	modelUpdateCmd.Flags().StringVar(&modelUpdateOpts.modelUpdateHost, "host", "", "Host the model was wrapped on (see 'tinfoil container hosts') [required]")
	modelUpdateCmd.Flags().StringVar(&modelUpdateOpts.modelUpdateCommit, "commit", "", "Hugging Face commit SHA to update to (defaults to the repo's latest commit)")
	modelUpdateCmd.Flags().StringVar(&modelUpdateOpts.modelUpdateHFToken, "hf-token", "", "Hugging Face token (visible in ps; prefer --hf-token-file or stdin)")
	modelUpdateCmd.Flags().StringVar(&modelUpdateOpts.modelUpdateHFTokenFile, "hf-token-file", "", "Read the Hugging Face token from this file (use - for stdin)")
	modelUpdateCmd.Flags().BoolVar(&modelUpdateOpts.modelUpdateWait, "wait", false, "Poll until the wrap job finishes and print the config block")
	_ = modelUpdateCmd.MarkFlagRequired("host")
	return modelUpdateCmd
}

func newModelListCommand(newClient authenticatedClientFactory, modelListOpts *modelListOptions, outputOpts *outputOptions) *cobra.Command {
	modelListCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List model wrap jobs in the organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			var query url.Values
			if modelListOpts.modelListLimit > 0 {
				query = url.Values{"limit": []string{strconv.Itoa(modelListOpts.modelListLimit)}}
			}
			var list []modelWrapJobView
			if _, err := client.do("GET", "/api/models/wrap", query, nil, &list); err != nil {
				return err
			}
			return renderModelWrapJobs(commandStreams(cmd), outputOpts, list)
		},
	}
	modelListCmd.Flags().IntVar(&modelListOpts.modelListLimit, "limit", 0, "Maximum number of jobs to list (server default 20, max 200)")
	return modelListCmd
}

func newModelStatusCommand(pollingOpts *pollingOptions, newClient authenticatedClientFactory, modelStatusOpts *modelStatusOptions, outputOpts *outputOptions) *cobra.Command {
	modelStatusCmd := &cobra.Command{
		Use:     "status [host] [job-id]",
		Aliases: []string{"get"},
		Short:   "Show the status of a model wrap job",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			job, err := fetchModelWrapJob(pollingOpts, commandStreams(cmd), client, args[0], args[1], modelStatusOpts.modelStatusWait)
			if err != nil {
				return err
			}
			return finishModelWrapJob(commandStreams(cmd), outputOpts, job, modelStatusOpts.modelStatusLogs, modelStatusOpts.modelStatusWait)
		},
	}
	modelStatusCmd.Flags().BoolVar(&modelStatusOpts.modelStatusWait, "wait", false, "Poll until the wrap job finishes")
	modelStatusCmd.Flags().BoolVar(&modelStatusOpts.modelStatusLogs, "logs", false, "Include the wrap job logs")
	return modelStatusCmd
}

func newModelDeleteCommand(newClient authenticatedClientFactory) *cobra.Command {
	modelDeleteCmd := &cobra.Command{
		Use:     "delete [host] [job-id]",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a wrap job and its artifact once unused",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient(commandStreams(cmd))
			if err != nil {
				return err
			}
			host, jobID := args[0], args[1]
			if _, err := client.do("DELETE", pathf("/api/models/wrap/%s/%s", host, jobID), nil, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(commandStreams(cmd).out, "Deleted model wrap job %s on %s\n", jobID, host)
			return nil
		},
	}

	return modelDeleteCmd
}

func readHFToken(cmd *cobra.Command) (string, error) {
	hasInline := cmd.Flags().Changed("hf-token")
	hasFile := cmd.Flags().Changed("hf-token-file")

	if hasInline && hasFile {
		return "", fmt.Errorf("--hf-token and --hf-token-file are mutually exclusive")
	}
	if hasFile {
		file, err := cmd.Flags().GetString("hf-token-file")
		if err != nil {
			return "", err
		}
		if file == "-" {
			data, err := io.ReadAll(commandStreams(cmd).in)
			if err != nil {
				return "", fmt.Errorf("reading stdin: %w", err)
			}
			return strings.TrimSpace(string(data)), nil
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", file, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return cmd.Flags().GetString("hf-token")
}

func modelWrapFinished(status string) bool {
	return status != "pending" && status != "running"
}

// fetchModelWrapJob reads the job's current state, polling to a terminal
// status when wait is set.
func fetchModelWrapJob(pollingOpts *pollingOptions, streams commandIO, client *cpClient, host, jobID string, wait bool) (modelWrapJobView, error) {
	if wait {
		job, err := waitForModelWrap(pollingOpts, streams, client, host, jobID)
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
func finishModelWrapJob(streams commandIO, outputOpts *outputOptions, job modelWrapJobView, showLogs, waited bool) error {
	if err := renderModelWrapJob(streams, outputOpts, job, showLogs); err != nil {
		return err
	}
	if waited && job.Status == "failed" {
		return fmt.Errorf("model wrap failed")
	}
	return nil
}

// runModelWrapJob submits a wrap job, optionally polls it to a terminal
// status, and finishes it, running epilogue on the rendered job. A waited-on
// failure skips epilogue, which only concerns completed jobs.
func runModelWrapJob(pollingOpts *pollingOptions, streams commandIO, outputOpts *outputOptions, client *cpClient, body map[string]any, wait bool, epilogue func(modelWrapJobView)) error {
	var job modelWrapJobView
	if _, err := client.do("POST", "/api/models/wrap", nil, body, &job); err != nil {
		return err
	}
	if wait {
		finished, err := waitForModelWrap(pollingOpts, streams, client, job.Host, job.JobID)
		if err != nil {
			return err
		}
		job = *finished
	}
	if err := finishModelWrapJob(streams, outputOpts, job, false, wait); err != nil {
		return err
	}
	if epilogue != nil {
		epilogue(job)
	}
	return nil
}

// modelWrapSearchWindow is the server's maximum list size; the API offers no
// pagination or repo filter, so lookups see at most this many recent jobs.
const modelWrapSearchWindow = 200

// latestCompleteModelWrap returns the newest completed wrap job for repo on
// host among the organization's most recent jobs, or nil when none exists.
// Jobs are compared by start time rather than list position so the result
// doesn't depend on the server's response ordering.
func latestCompleteModelWrap(client *cpClient, repo, host string) (*modelWrapJobView, error) {
	query := url.Values{"limit": []string{strconv.Itoa(modelWrapSearchWindow)}}
	var list []modelWrapJobView
	if _, err := client.do("GET", "/api/models/wrap", query, nil, &list); err != nil {
		return nil, err
	}
	best := -1
	var bestAt time.Time
	for i := range list {
		job := list[i]
		if job.Repo != repo || job.Host != host || job.Status != "complete" {
			continue
		}
		startedAt, _ := time.Parse(time.RFC3339, job.StartedAt) // zero on failure
		if best == -1 || startedAt.After(bestAt) {
			best, bestAt = i, startedAt
		}
	}
	if best == -1 {
		return nil, nil
	}
	job := list[best]
	return &job, nil
}

// resolveLatestHFCommit asks the controlplane's Hugging Face proxy for the
// latest commit on the repo's default branch.
func resolveLatestHFCommit(client *cpClient, repo, token string) (string, error) {
	owner, model, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || model == "" || strings.Contains(model, "/") {
		return "", fmt.Errorf("invalid repo %q: expected owner/model", repo)
	}
	var headers map[string]string
	if token != "" {
		headers = map[string]string{"X-HuggingFace-Token": token}
	}
	var info struct {
		SHA string `json:"sha"`
	}
	if _, err := client.doWithHeaders("GET", pathf("/api/huggingface/models/%s/%s", owner, model), nil, headers, nil, &info); err != nil {
		return "", err
	}
	if info.SHA == "" {
		return "", fmt.Errorf("Hugging Face did not report a latest commit for %s", repo)
	}
	return info.SHA, nil
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	if commit == "" {
		return "?"
	}
	return commit
}

// waitForModelWrap polls the job until it reaches a terminal status,
// reporting status changes on stderr so stdout stays machine-readable.
func waitForModelWrap(pollingOpts *pollingOptions, streams commandIO, client *cpClient, host, jobID string) (*modelWrapJobView, error) {
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
			fmt.Fprintf(streams.err, "Wrap job %s: %s (large models can take several minutes)\n", jobID, job.Status)
			lastStatus = job.Status
		}
		time.Sleep(pollingOpts.modelWrapPollInterval)
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

func renderModelWrapJob(streams commandIO, outputOpts *outputOptions, job modelWrapJobView, showLogs bool) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, job)
	}
	fmt.Fprintf(streams.out, "Job ID:   %s\n", job.JobID)
	fmt.Fprintf(streams.out, "Host:     %s\n", job.Host)
	fmt.Fprintf(streams.out, "Repo:     %s\n", job.Repo)
	if job.Commit != "" {
		fmt.Fprintf(streams.out, "Commit:   %s\n", job.Commit)
	}
	fmt.Fprintf(streams.out, "Status:   %s\n", job.Status)
	if job.StartedAt != "" {
		fmt.Fprintf(streams.out, "Started:  %s\n", job.StartedAt)
	}
	if job.EndedAt != nil {
		fmt.Fprintf(streams.out, "Ended:    %s\n", *job.EndedAt)
	}
	if job.Error != "" {
		fmt.Fprintf(streams.out, "Error:    %s\n", job.Error)
	}

	switch {
	case job.Status == "complete" && job.RootHash != "":
		fmt.Fprintf(streams.out, "\nAdd this to tinfoil-config.yml:\n\n")
		fmt.Fprintf(streams.out, "models:\n")
		fmt.Fprintf(streams.out, "  - name: %q\n", modelNameFromRepo(job.Repo))
		fmt.Fprintf(streams.out, "    repo: %q\n", job.Repo+"@"+job.Commit)
		fmt.Fprintf(streams.out, "    mpk: %q\n", modelMPK(job))
		fmt.Fprintf(streams.out, "\nThe verified weights are mounted in the enclave at:\n")
		fmt.Fprintf(streams.out, "  /tinfoil/mpk/mpk-%s\n", job.RootHash)
	case !modelWrapFinished(job.Status):
		fmt.Fprintf(streams.out, "\nPoll with `tinfoil model status %s %s`.\n", job.Host, job.JobID)
	}

	if showLogs && job.Logs != "" {
		fmt.Fprintf(streams.out, "\nLogs:\n%s\n", strings.TrimRight(job.Logs, "\n"))
	}
	return nil
}

func renderModelWrapJobs(streams commandIO, outputOpts *outputOptions, list []modelWrapJobView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(streams, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(streams.out, "No model wrap jobs.")
		return nil
	}
	fmt.Fprintf(streams.out, "%-16s  %-12s  %-32s  %-12s  %-8s  %s\n", "JOB ID", "HOST", "REPO", "COMMIT", "STATUS", "STARTED")
	for _, job := range list {
		commit := job.Commit
		if commit == "" {
			commit = "-"
		}
		fmt.Fprintf(streams.out, "%-16s  %-12s  %-32s  %-12s  %-8s  %s\n",
			job.JobID, truncate(job.Host, 12), truncate(job.Repo, 32),
			truncate(commit, 12), job.Status, truncate(job.StartedAt, 19),
		)
	}
	return nil
}
