package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	deploymentAutoUpdateOff    = "off"
	deploymentAutoUpdateLatest = "latest"

	deploymentInstanceStatusSkipped = "skipped"
	deploymentInstanceStatusFailed  = "failed"
)

type deploymentView struct {
	ID             string  `json:"id"`
	Repo           string  `json:"repo"`
	GroupName      *string `json:"group_name"`
	GroupOrder     int32   `json:"group_order"`
	DisplayOrder   int32   `json:"display_order"`
	AutoUpdate     string  `json:"auto_update"`
	DefaultStaging bool    `json:"default_staging"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	InstanceCount  int32   `json:"instance_count"`
	ReadyCount     int32   `json:"ready_count"`
	FailedCount    int32   `json:"failed_count"`
	StoppedCount   int32   `json:"stopped_count"`
	DeployingCount int32   `json:"deploying_count"`
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
	deploymentSettingsAutoUpdate     string
	deploymentSettingsDefaultStaging string

	deploymentGroupName         string
	deploymentGroupOrder        int32
	deploymentGroupDisplayOrder int32
	deploymentGroupUngroup      bool

	deploymentUpdateTag         string
	deploymentUpdateStaging     string
	deploymentUpdateInstanceIDs []string
)

func init() {
	rootCmd.AddCommand(deploymentCmd)
	deploymentCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	deploymentCmd.AddCommand(deploymentListCmd)
	deploymentCmd.AddCommand(deploymentGetCmd)
	deploymentCmd.AddCommand(deploymentSettingsCmd)
	deploymentCmd.AddCommand(deploymentGroupCmd)
	deploymentCmd.AddCommand(deploymentUpdateCmd)

	deploymentSettingsCmd.Flags().StringVar(
		&deploymentSettingsAutoUpdate,
		"auto-update",
		"",
		"Auto-update policy: off or latest",
	)
	deploymentSettingsCmd.Flags().StringVar(
		&deploymentSettingsDefaultStaging,
		"default-staging",
		"",
		"Default staging mode for deployment updates (true/false)",
	)

	deploymentGroupCmd.Flags().StringVar(&deploymentGroupName, "name", "", "Group name to assign")
	deploymentGroupCmd.Flags().BoolVar(&deploymentGroupUngroup, "ungroup", false, "Remove the deployment from any group")
	deploymentGroupCmd.Flags().Int32Var(&deploymentGroupOrder, "group-order", 0, "Order of the group itself")
	deploymentGroupCmd.Flags().Int32Var(&deploymentGroupDisplayOrder, "display-order", 0, "Display order of the deployment")

	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateTag, "tag", "", "Repository release tag to deploy")
	deploymentUpdateCmd.Flags().StringVar(&deploymentUpdateStaging, "staging", "", "Override staging mode (true/false)")
	deploymentUpdateCmd.Flags().StringArrayVar(
		&deploymentUpdateInstanceIDs,
		"instance",
		nil,
		"Container instance ID to update; may be repeated (default: all instances)",
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
		if deploymentSettingsAutoUpdate != "" {
			policy := strings.ToLower(strings.TrimSpace(deploymentSettingsAutoUpdate))
			if policy != deploymentAutoUpdateOff && policy != deploymentAutoUpdateLatest {
				return fmt.Errorf("--auto-update must be %q or %q", deploymentAutoUpdateOff, deploymentAutoUpdateLatest)
			}
			body["auto_update"] = policy
		}
		if deploymentSettingsDefaultStaging != "" {
			staging, err := parseTriBool(deploymentSettingsDefaultStaging)
			if err != nil {
				return fmt.Errorf("--default-staging: %w", err)
			}
			body["default_staging"] = staging
		}
		if len(body) == 0 {
			return fmt.Errorf("specify --auto-update or --default-staging")
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

var deploymentGroupCmd = &cobra.Command{
	Use:   "group [id|owner/repo]",
	Short: "Move a repository deployment into or out of a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !deploymentGroupUngroup && deploymentGroupName == "" {
			return fmt.Errorf("specify --name <group> or --ungroup")
		}
		if deploymentGroupUngroup && deploymentGroupName != "" {
			return fmt.Errorf("--name and --ungroup are mutually exclusive")
		}

		client, err := authedClient()
		if err != nil {
			return err
		}
		deployment, err := resolveDeployment(client, args[0])
		if err != nil {
			return err
		}

		groupOrder := deployment.GroupOrder
		if cmd.Flags().Changed("group-order") {
			groupOrder = deploymentGroupOrder
		}
		displayOrder := deployment.DisplayOrder
		if cmd.Flags().Changed("display-order") {
			displayOrder = deploymentGroupDisplayOrder
		}
		var groupName *string
		if !deploymentGroupUngroup {
			groupName = &deploymentGroupName
		}
		updated, err := moveDeploymentToGroup(client, deployment.ID, groupName, groupOrder, displayOrder)
		if err != nil {
			return err
		}
		updated = preserveDeploymentCounts(updated, *deployment)
		return renderDeployment(updated)
	},
}

var deploymentUpdateCmd = &cobra.Command{
	Use:   "update [id|owner/repo]",
	Short: "Update all or selected instances of a repository deployment",
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

func resolveDeploymentForContainer(client *cpClient, container containerView) (*deploymentView, error) {
	if container.DeploymentID != "" {
		return resolveDeployment(client, container.DeploymentID)
	}
	if container.Repo != "" {
		return resolveDeployment(client, container.Repo)
	}
	return nil, fmt.Errorf("container %s is not linked to a repository deployment", container.Name)
}

func patchDeployment(client *cpClient, deploymentID string, body map[string]any) (deploymentView, error) {
	var updated deploymentView
	if _, err := client.do("PATCH", pathf("/api/deployments/%s", deploymentID), nil, body, &updated); err != nil {
		return deploymentView{}, err
	}
	return updated, nil
}

func setDeploymentAutoUpdate(client *cpClient, deployment deploymentView, enabled bool) (deploymentView, error) {
	policy := deploymentAutoUpdateOff
	if enabled {
		policy = deploymentAutoUpdateLatest
	}
	return patchDeployment(client, deployment.ID, map[string]any{"auto_update": policy})
}

func moveDeploymentToGroup(
	client *cpClient,
	deploymentID string,
	groupName *string,
	groupOrder, displayOrder int32,
) (deploymentView, error) {
	body := map[string]any{
		"group_name":    groupName,
		"group_order":   groupOrder,
		"display_order": displayOrder,
	}
	var updated deploymentView
	if _, err := client.do("PUT", pathf("/api/deployments/%s/group", deploymentID), nil, body, &updated); err != nil {
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
	fmt.Printf("Auto-update:     %s\n", deployment.AutoUpdate)
	fmt.Printf("Default staging: %v\n", deployment.DefaultStaging)
	if deployment.GroupName != nil {
		fmt.Printf("Group:           %s\n", *deployment.GroupName)
	}
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
	fmt.Printf("%-36s  %-9s  %-7s  %-9s  %-6s  %-12s  %s\n",
		"REPOSITORY", "INSTANCES", "READY", "DEPLOYING", "FAILED", "AUTO-UPDATE", "GROUP",
	)
	for _, deployment := range deployments {
		group := "-"
		if deployment.GroupName != nil {
			group = *deployment.GroupName
		}
		fmt.Printf("%-36s  %-9d  %-7d  %-9d  %-6d  %-12s  %s\n",
			truncate(deployment.Repo, 36),
			deployment.InstanceCount,
			deployment.ReadyCount,
			deployment.DeployingCount,
			deployment.FailedCount,
			deployment.AutoUpdate,
			group,
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
