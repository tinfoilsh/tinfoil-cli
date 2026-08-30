package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	deploymentInstanceStatusSkipped = "skipped"
	deploymentInstanceStatusFailed  = "failed"
)

type deploymentView struct {
	ID             string `json:"id"`
	Repo           string `json:"repo"`
	DefaultStaging bool   `json:"default_staging"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	InstanceCount  int32  `json:"instance_count"`
	ReadyCount     int32  `json:"ready_count"`
	FailedCount    int32  `json:"failed_count"`
	StoppedCount   int32  `json:"stopped_count"`
	DeployingCount int32  `json:"deploying_count"`
}

type deploymentInstanceResult struct {
	ContainerID string         `json:"container_id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Container   *containerView `json:"container,omitempty"`
}

type deploymentUpdateResponse struct {
	Results []deploymentInstanceResult `json:"results"`
}

var (
	deploymentSettingsDefaultStaging string

	deploymentUpdateTag            string
	deploymentUpdateStaging        string
	deploymentUpdatePromoteRelease string
	deploymentUpdateInstanceIDs    []string
)

func init() {
	rootCmd.AddCommand(deploymentCmd)
	deploymentCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	deploymentCmd.AddCommand(deploymentListCmd)
	deploymentCmd.AddCommand(deploymentGetCmd)
	deploymentCmd.AddCommand(deploymentSettingsCmd)
	deploymentCmd.AddCommand(deploymentUpdateCmd)

	deploymentSettingsCmd.Flags().StringVar(
		&deploymentSettingsDefaultStaging,
		"default-staging",
		"",
		"By default, hold eligible ready update candidates for manual acceptance (true/false)",
	)

	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateTag, "tag", "", "Repository release tag to deploy")
	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateStaging, "staging", "", "Hold eligible ready update candidates for manual acceptance (true/false)")
	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdatePromoteRelease, "promote-release", "", "Override latest-release promotion (true/false; server default: true)")
	deploymentUpdateCmd.Flags().StringArrayVar(
		&deploymentUpdateInstanceIDs,
		"instance",
		nil,
		"Eligible container instance ID to update; may be repeated (default: all eligible instances)",
	)
	_ = deploymentUpdateCmd.MarkFlagRequired("tag")

	silenceUsageRecursive(deploymentCmd)
}

var deploymentCmd = &cobra.Command{
	Use:          "deployment",
	Aliases:      []string{"deployments", "dep"},
	Short:        "Manage repository deployments",
	SilenceUsage: true,
}

var deploymentListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List repository deployments in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		deployments, err := listDeployments(client)
		if err != nil {
			return err
		}
		return renderDeployments(deployments)
	},
}

var deploymentGetCmd = &cobra.Command{
	Use:   "get [id|owner/repo]",
	Short: "Show a repository deployment",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		deployment, err := resolveDeployment(client, args[0])
		if err != nil {
			return err
		}
		return renderDeployment(*deployment)
	},
}

var deploymentSettingsCmd = &cobra.Command{
	Use:     "settings [id|owner/repo]",
	Aliases: []string{"set"},
	Short:   "Update repository deployment settings",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{}
		if deploymentSettingsDefaultStaging != "" {
			staging, err := parseTriBool(deploymentSettingsDefaultStaging)
			if err != nil {
				return fmt.Errorf("--default-staging: %w", err)
			}
			body["default_staging"] = staging
		}
		if len(body) == 0 {
			return fmt.Errorf("specify --default-staging")
		}

		client, err := authedClient()
		if err != nil {
			return err
		}
		deployment, err := resolveDeployment(client, args[0])
		if err != nil {
			return err
		}
		updated, err := patchDeployment(client, deployment.ID, body)
		if err != nil {
			return err
		}
		updated = preserveDeploymentCounts(updated, *deployment)
		return renderDeployment(updated)
	},
}

var deploymentUpdateCmd = &cobra.Command{
	Use:   "update [id|owner/repo]",
	Short: "Create update candidates for all or selected eligible instances",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		deployment, err := resolveDeployment(client, args[0])
		if err != nil {
			return err
		}

		body := map[string]any{"tag": deploymentUpdateTag}
		if cmd.Flags().Changed("staging") {
			staging, err := parseTriBool(deploymentUpdateStaging)
			if err != nil {
				return fmt.Errorf("--staging: %w", err)
			}
			body["staging"] = staging
		}
		if cmd.Flags().Changed("promote-release") {
			promoteRelease, err := parseTriBool(deploymentUpdatePromoteRelease)
			if err != nil {
				return fmt.Errorf("--promote-release: %w", err)
			}
			body["promote_release"] = promoteRelease
		}
		if len(deploymentUpdateInstanceIDs) > 0 {
			body["instance_ids"] = deploymentUpdateInstanceIDs
		}

		response, err := updateDeploymentInstances(client, deployment.ID, body)
		if err != nil {
			return err
		}
		return renderDeploymentUpdateResults(response.Results)
	},
}

func listDeployments(client *cpClient) ([]deploymentView, error) {
	var deployments []deploymentView
	if _, err := client.do("GET", "/api/deployments", nil, nil, &deployments); err != nil {
		return nil, err
	}
	return deployments, nil
}

func resolveDeployment(client *cpClient, identifier string) (*deploymentView, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("deployment identifier is empty")
	}

	deployments, err := listDeployments(client)
	if err != nil {
		return nil, err
	}
	for i := range deployments {
		if deployments[i].ID == identifier || deployments[i].Repo == identifier {
			return &deployments[i], nil
		}
	}
	return nil, fmt.Errorf("no deployment matching %q (use the deployment ID, owner/repo, or `tinfoil deployment list`)", identifier)
}

func patchDeployment(client *cpClient, deploymentID string, body map[string]any) (deploymentView, error) {
	var updated deploymentView
	if _, err := client.do("PATCH", pathf("/api/deployments/%s", deploymentID), nil, body, &updated); err != nil {
		return deploymentView{}, err
	}
	return updated, nil
}

func updateDeploymentInstances(client *cpClient, deploymentID string, body map[string]any) (deploymentUpdateResponse, error) {
	var response deploymentUpdateResponse
	if _, err := client.do("POST", pathf("/api/deployments/%s/update", deploymentID), nil, body, &response); err != nil {
		return deploymentUpdateResponse{}, err
	}
	return response, nil
}

func preserveDeploymentCounts(updated, current deploymentView) deploymentView {
	updated.InstanceCount = current.InstanceCount
	updated.ReadyCount = current.ReadyCount
	updated.FailedCount = current.FailedCount
	updated.StoppedCount = current.StoppedCount
	updated.DeployingCount = current.DeployingCount
	return updated
}

func renderDeployment(deployment deploymentView) error {
	if outputFormat == "json" {
		return printJSON(deployment)
	}
	fmt.Printf("ID:              %s\n", deployment.ID)
	fmt.Printf("Repository:      %s\n", deployment.Repo)
	fmt.Printf("Instances:       %d\n", deployment.InstanceCount)
	fmt.Printf("Ready:           %d\n", deployment.ReadyCount)
	fmt.Printf("Deploying:       %d\n", deployment.DeployingCount)
	fmt.Printf("Failed:          %d\n", deployment.FailedCount)
	fmt.Printf("Stopped:         %d\n", deployment.StoppedCount)
	fmt.Printf("Default staging: %v\n", deployment.DefaultStaging)
	return nil
}

func renderDeployments(deployments []deploymentView) error {
	if outputFormat == "json" {
		return printJSON(deployments)
	}
	if len(deployments) == 0 {
		fmt.Println("No deployments.")
		return nil
	}
	fmt.Printf("%-36s  %-9s  %-7s  %-9s  %s\n",
		"REPOSITORY", "INSTANCES", "READY", "DEPLOYING", "FAILED",
	)
	for _, deployment := range deployments {
		fmt.Printf("%-36s  %-9d  %-7d  %-9d  %d\n",
			truncate(deployment.Repo, 36),
			deployment.InstanceCount,
			deployment.ReadyCount,
			deployment.DeployingCount,
			deployment.FailedCount,
		)
	}
	return nil
}

func renderDeploymentUpdateResults(results []deploymentInstanceResult) error {
	if outputFormat == "json" {
		if err := printJSON(deploymentUpdateResponse{Results: results}); err != nil {
			return err
		}
	}
	if len(results) == 0 {
		if outputFormat != "json" {
			fmt.Println("No deployment instances were selected.")
		}
		return nil
	}
	if outputFormat != "json" {
		fmt.Printf("%-24s  %-10s  %s\n", "NAME", "STATUS", "DETAIL")
	}
	failed, skipped := 0, 0
	for _, result := range results {
		if outputFormat != "json" {
			detail := result.Error
			if detail == "" {
				detail = result.ContainerID
			}
			fmt.Printf("%-24s  %-10s  %s\n", truncate(result.Name, 24), result.Status, detail)
		}
		switch result.Status {
		case deploymentInstanceStatusFailed:
			failed++
		case deploymentInstanceStatusSkipped:
			skipped++
		}
	}
	if failed > 0 || skipped > 0 {
		return fmt.Errorf("deployment update incomplete: %d failed, %d skipped", failed, skipped)
	}
	return nil
}
