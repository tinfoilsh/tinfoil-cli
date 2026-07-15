package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

type modelwrapView struct {
	ID         string `json:"id"`
	JobID      string `json:"job_id"`
	RecordID   string `json:"record_id"`
	Host       string `json:"host"`
	Repo       string `json:"repo"`
	Commit     string `json:"commit"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	RootHash   string `json:"root_hash,omitempty"`
	Offset     int64  `json:"offset,omitempty"`
	VerityUUID string `json:"verity_uuid,omitempty"`
	StartedAt  string `json:"started_at"`
	EndedAt    string `json:"ended_at,omitempty"`
}

var (
	modelOutputFormat string
	modelListLimit    int
	modelDeleteHost   string
)

func init() {
	rootCmd.AddCommand(modelCmd)
	modelCmd.PersistentFlags().StringVarP(&modelOutputFormat, "output", "o", "table", "Output format: table or json")
	modelCmd.AddCommand(modelListCmd)
	modelCmd.AddCommand(modelDeleteCmd)
	modelListCmd.Flags().IntVar(&modelListLimit, "limit", 20, "Maximum number of model wraps to return (1-200)")
	modelDeleteCmd.Flags().StringVar(&modelDeleteHost, "host", "", "Host name, used to disambiguate duplicate model wraps")
	silenceUsageRecursive(modelCmd)
}

var modelCmd = &cobra.Command{
	Use:          "model",
	Aliases:      []string{"models"},
	Short:        "Manage prepared model weights",
	SilenceUsage: true,
}

var modelListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List prepared model weights in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		if modelListLimit < 1 || modelListLimit > 200 {
			return fmt.Errorf("--limit must be between 1 and 200")
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		models, err := listModelwraps(client, modelListLimit)
		if err != nil {
			return err
		}
		return renderModelwraps(models)
	},
}

var modelDeleteCmd = &cobra.Command{
	Use:     "delete [job-id|owner/model@revision]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete prepared model weights",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		deleted, err := deleteModelwrap(client, args[0], modelDeleteHost)
		if err != nil {
			return err
		}
		fmt.Printf("Deleted model %s from %s (job %s)\n", modelwrapTarget(deleted), deleted.Host, deleted.ID)
		return nil
	},
}

func listModelwraps(client *cpClient, limit int) ([]modelwrapView, error) {
	query := url.Values{"limit": []string{fmt.Sprintf("%d", limit)}}
	var models []modelwrapView
	if _, err := client.do(http.MethodGet, "/api/models/wrap", query, nil, &models); err != nil {
		return nil, err
	}
	for i := range models {
		if models[i].JobID != "" {
			models[i].ID = models[i].JobID
		}
	}
	return models, nil
}

func deleteModelwrap(client *cpClient, identifier, host string) (modelwrapView, error) {
	models, err := listModelwraps(client, 200)
	if err != nil {
		return modelwrapView{}, err
	}
	model, err := resolveModelwrapFromList(models, identifier, host)
	if err != nil {
		return modelwrapView{}, err
	}
	if _, err := client.do(
		http.MethodDelete,
		pathf("/api/models/wrap/%s/%s", model.Host, model.ID),
		nil,
		nil,
		nil,
	); err != nil {
		return modelwrapView{}, err
	}
	return model, nil
}

func resolveModelwrapFromList(models []modelwrapView, identifier, host string) (modelwrapView, error) {
	identifier = strings.TrimSpace(identifier)
	host = strings.TrimSpace(host)
	if identifier == "" {
		return modelwrapView{}, fmt.Errorf("model identifier is empty")
	}
	matches := make([]modelwrapView, 0, 2)
	for _, model := range models {
		if host != "" && model.Host != host {
			continue
		}
		if model.ID == identifier || model.JobID == identifier || model.RecordID == identifier || modelwrapTarget(model) == identifier {
			matches = append(matches, model)
		}
	}
	switch len(matches) {
	case 0:
		return modelwrapView{}, fmt.Errorf("no model wrap matching %q", identifier)
	case 1:
		return matches[0], nil
	default:
		return modelwrapView{}, fmt.Errorf("multiple model wraps match %q; use the job ID or pass --host", identifier)
	}
}

func modelwrapTarget(model modelwrapView) string {
	if model.Commit == "" {
		return model.Repo
	}
	return model.Repo + "@" + model.Commit
}

func renderModelwraps(models []modelwrapView) error {
	if modelOutputFormat == "json" {
		return printJSON(models)
	}
	if len(models) == 0 {
		fmt.Println("No prepared models.")
		return nil
	}
	fmt.Printf("%-12s  %-20s  %-10s  %-48s  %s\n", "JOB ID", "HOST", "STATUS", "MODEL", "STARTED")
	for _, model := range models {
		fmt.Printf("%-12s  %-20s  %-10s  %-48s  %s\n",
			truncate(model.ID, 12), truncate(model.Host, 20), model.Status,
			truncate(modelwrapTarget(model), 48), model.StartedAt,
		)
	}
	return nil
}
