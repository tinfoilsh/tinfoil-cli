package main

import (
	"fmt"
	"os"
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
	RunningCount   int32  `json:"running_count"`
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
	deploymentUpdateYes            bool
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
		"Hold new versions for manual acceptance by default instead of switching traffic automatically (true/false)",
	)

	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateTag, "tag", "", "Release tag to update to")
	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateStaging, "staging", "", "Hold new versions for manual acceptance instead of switching traffic automatically (true/false)")
	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdatePromoteRelease, "promote-release", "", "Promote the deployed tag to the repository's latest release when it goes live (default true; pass false to decline)")
	deploymentUpdateCmd.Flags().StringArrayVar(
		&deploymentUpdateInstanceIDs,
		"instance",
		nil,
		"Running container instance ID to update; may be repeated (default: all running instances)",
	)
	deploymentUpdateCmd.Flags().BoolVar(&deploymentUpdateYes, "yes", false, "Skip the downtime confirmation for instances that must be replaced")
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
	Short: "Update every running instance of a repository to a tag",
	Long: `Update all running container instances that use this repository, or only
those named with --instance. Instances that must be replaced (multi-GPU or
persistent volumes) go down while they redeploy; the command lists them and
asks for confirmation unless --yes is given. Stopped and failed instances are
skipped; bring those up with "tinfoil container deploy".`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{
			"tag": deploymentUpdateTag,
		}
		if err := setPromoteRelease(cmd, body, deploymentUpdatePromoteRelease); err != nil {
			return err
		}
		if cmd.Flags().Changed("staging") {
			staging, err := parseTriBool(deploymentUpdateStaging)
			if err != nil {
				return fmt.Errorf("--staging: %w", err)
			}
			body["staging"] = staging
		}
		if len(deploymentUpdateInstanceIDs) > 0 {
			body["instance_ids"] = deploymentUpdateInstanceIDs
		}

		client, err := authedClient()
		if err != nil {
			return err
		}
		deployment, err := resolveDeployment(client, args[0])
		if err != nil {
			return err
		}

		replaced, err := replaceStrategyInstances(client, deployment.Repo, deploymentUpdateInstanceIDs)
		if err != nil {
			return err
		}
		if len(replaced) > 0 {
			if err := confirmDeploymentDowntime(replaced); err != nil {
				return err
			}
			body["confirm_downtime"] = true
		}

		response, err := updateDeploymentInstances(client, deployment.ID, body)
		if err != nil {
			return err
		}
		return renderDeploymentUpdateResults(response.Results)
	},
}

// replaceStrategyInstances lists the running instances of repo (or the
// selected ones) whose update replaces the running enclave and so causes
// downtime.
func replaceStrategyInstances(client *cpClient, repo string, selected []string) ([]containerView, error) {
	var list []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &list); err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, id := range selected {
		wanted[id] = true
	}
	var out []containerView
	for _, c := range list {
		if !strings.EqualFold(c.Repo, repo) || c.Status != statusRunning || c.UpdateStrategy != updateStrategyReplace {
			continue
		}
		if len(wanted) > 0 && !wanted[c.ID] {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func confirmDeploymentDowntime(instances []containerView) error {
	fmt.Fprintln(os.Stderr, "This update will cause downtime for:")
	for _, c := range instances {
		fmt.Fprintf(os.Stderr, "  %-24s %s\n", c.Name, replaceReason(c))
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "These instances cannot run two versions at once. Each is stopped first and the")
	fmt.Fprintln(os.Stderr, "new version deploys in its place; each is unreachable until it is Running.")
	fmt.Fprintln(os.Stderr)
	return confirmYes(deploymentUpdateYes, "deployment update")
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
	updated.RunningCount = current.RunningCount
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
	fmt.Printf("Running:         %d\n", deployment.RunningCount)
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
	fmt.Printf("%-36s  %-9s  %-7s  %-11s  %s\n",
		"REPOSITORY", "INSTANCES", "RUNNING", "DEPLOYING", "FAILED",
	)
	for _, deployment := range deployments {
		fmt.Printf("%-36s  %-9d  %-7d  %-11d  %d\n",
			truncate(deployment.Repo, 36),
			deployment.InstanceCount,
			deployment.RunningCount,
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
