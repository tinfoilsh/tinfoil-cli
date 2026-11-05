package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	projectInstanceStatusSkipped = "skipped"
	projectInstanceStatusFailed  = "failed"
)

type projectView struct {
	ID             string `json:"id"`
	Repo           string `json:"repo"`
	HoldByDefault  bool   `json:"hold_by_default"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	InstanceCount  int32  `json:"instance_count"`
	RunningCount   int32  `json:"running_count"`
	FailedCount    int32  `json:"failed_count"`
	StoppedCount   int32  `json:"stopped_count"`
	DeployingCount int32  `json:"deploying_count"`
}

type projectInstanceResult struct {
	ContainerID string         `json:"container_id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Container   *containerView `json:"container,omitempty"`
}

type projectUpdateResponse struct {
	Results []projectInstanceResult `json:"results"`
}

func newProjectCommand(outputOpts *outputOptions) *cobra.Command {
	projectCmd := &cobra.Command{
		Use:     "project",
		Aliases: []string{"projects"},
		Short:   "Manage groups of containers that share a config repo",
	}
	projectCmd.PersistentFlags().StringVarP(&outputOpts.outputFormat, "output", "o", "table", "Output format: table or json")
	projectCmd.AddCommand(newProjectListCommand(outputOpts))
	projectCmd.AddCommand(newProjectGetCommand(outputOpts))
	projectCmd.AddCommand(newProjectSettingsCommand(outputOpts, &projectSettingsOptions{}))
	projectCmd.AddCommand(newProjectUpdateCommand(outputOpts, &projectUpdateOptions{}))
	projectCmd.AddCommand(newProjectStorageCommand(outputOpts))
	return projectCmd
}

func newProjectListCommand(outputOpts *outputOptions) *cobra.Command {
	projectListCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List projects in the current organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if err != nil {
				return err
			}
			projects, err := listProjects(client)
			if err != nil {
				return err
			}
			return renderProjects(outputOpts, projects)
		},
	}

	return projectListCmd
}

func newProjectGetCommand(outputOpts *outputOptions) *cobra.Command {
	projectGetCmd := &cobra.Command{
		Use:   "get [id|owner/repo]",
		Short: "Show a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := authedClient()
			if err != nil {
				return err
			}
			project, err := resolveProject(client, args[0])
			if err != nil {
				return err
			}
			return renderProject(outputOpts, *project)
		},
	}

	return projectGetCmd
}

func newProjectSettingsCommand(outputOpts *outputOptions, projectSettingsOpts *projectSettingsOptions) *cobra.Command {
	projectSettingsCmd := &cobra.Command{
		Use:     "settings [id|owner/repo]",
		Aliases: []string{"set"},
		Short:   "Update project settings",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if projectSettingsOpts.projectSettingsHoldByDefault != "" {
				hold, err := parseTriBool(projectSettingsOpts.projectSettingsHoldByDefault)
				if err != nil {
					return fmt.Errorf("--hold-by-default: %w", err)
				}
				body["hold_by_default"] = hold
			}
			if len(body) == 0 {
				return fmt.Errorf("specify --hold-by-default")
			}

			client, err := authedClient()
			if err != nil {
				return err
			}
			project, err := resolveProject(client, args[0])
			if err != nil {
				return err
			}
			updated, err := patchProject(client, project.ID, body)
			if err != nil {
				return err
			}
			updated = preserveProjectCounts(updated, *project)
			return renderProject(outputOpts, updated)
		},
	}
	projectSettingsCmd.Flags().StringVar(
		&projectSettingsOpts.projectSettingsHoldByDefault,
		"hold-by-default",
		"",
		"Hold new versions for review by default (true/false)",
	)
	projectSettingsCmd.Flags().Lookup("hold-by-default").NoOptDefVal = "true"
	return projectSettingsCmd
}

func newProjectUpdateCommand(outputOpts *outputOptions, projectUpdateOpts *projectUpdateOptions) *cobra.Command {
	projectUpdateCmd := &cobra.Command{
		Use:   "update [id|owner/repo]",
		Short: "Update every running instance of a project to a tag",
		Long:  `Stopped and failed instances are skipped; start them with "tinfoil container deploy".`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{
				"tag": projectUpdateOpts.projectUpdateTag,
			}
			if err := setMarkLatestRelease(cmd, body, projectUpdateOpts.projectUpdateMarkLatestRelease); err != nil {
				return err
			}
			if cmd.Flags().Changed("hold") {
				hold, err := parseTriBool(projectUpdateOpts.projectUpdateHold)
				if err != nil {
					return fmt.Errorf("--hold: %w", err)
				}
				body["hold"] = hold
			}
			if len(projectUpdateOpts.projectUpdateInstanceIDs) > 0 {
				body["instance_ids"] = projectUpdateOpts.projectUpdateInstanceIDs
			}

			client, err := authedClient()
			if err != nil {
				return err
			}
			project, err := resolveProject(client, args[0])
			if err != nil {
				return err
			}

			response, err := updateProjectInstances(outputOpts, projectUpdateOpts, client, project.ID, body)
			if err != nil {
				if len(response.Results) > 0 {
					return errors.Join(err, renderProjectUpdateResults(outputOpts, response.Results))
				}
				return err
			}
			return renderProjectUpdateResults(outputOpts, response.Results)
		},
	}
	projectUpdateCmd.Flags().StringVar(&projectUpdateOpts.projectUpdateTag, "tag", "", "Release tag to update to")
	projectUpdateCmd.Flags().StringVar(&projectUpdateOpts.projectUpdateHold, "hold", "", "Hold the new version for review (default: the project's setting)")
	projectUpdateCmd.Flags().Lookup("hold").NoOptDefVal = "true"
	projectUpdateCmd.Flags().StringVar(&projectUpdateOpts.projectUpdateMarkLatestRelease, "mark-latest", "", "Mark the tag as the repo's latest GitHub release once running (default true)")
	projectUpdateCmd.Flags().StringArrayVar(
		&projectUpdateOpts.projectUpdateInstanceIDs,
		"instance",
		nil,
		"Instance ID to update; may be repeated (default: all running)",
	)
	projectUpdateCmd.Flags().BoolVar(&projectUpdateOpts.projectUpdateYes, "yes", false, "Approve the update plan, including any downtime")
	_ = projectUpdateCmd.MarkFlagRequired("tag")
	return projectUpdateCmd
}

func listProjects(client *cpClient) ([]projectView, error) {
	var projects []projectView
	if _, err := client.do("GET", "/api/containers/projects", nil, nil, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func resolveProject(client *cpClient, identifier string) (*projectView, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("project identifier is empty")
	}

	projects, err := listProjects(client)
	if err != nil {
		return nil, err
	}
	for i := range projects {
		if projects[i].ID == identifier || projects[i].Repo == identifier {
			return &projects[i], nil
		}
	}
	return nil, fmt.Errorf("no project matching %q (use the project ID, owner/repo, or `tinfoil project list`)", identifier)
}

func patchProject(client *cpClient, projectID string, body map[string]any) (projectView, error) {
	var updated projectView
	if _, err := client.do("PATCH", pathf("/api/containers/projects/%s", projectID), nil, body, &updated); err != nil {
		return projectView{}, err
	}
	return updated, nil
}

func updateProjectInstances(outputOpts *outputOptions, projectUpdateOpts *projectUpdateOptions, client *cpClient, projectID string, body map[string]any) (projectUpdateResponse, error) {
	var response projectUpdateResponse
	var excluded []projectInstanceResult
	seen := make(map[string]bool)
	replan := func() (updateReview, error) {
		review, err := planProjectUpdate(client, projectID, body)
		if err != nil {
			return review, err
		}
		for _, result := range review.project.Results {
			if result.Status == planStatusPlanned || seen[result.InstanceID] {
				continue
			}
			detail := "not executed: excluded by update plan"
			if result.Error != nil {
				detail += ": " + secretDeliveryMessage(*result.Error)
			}
			excluded = append(excluded, projectInstanceResult{ContainerID: result.InstanceID, Name: result.Name, Status: result.Status, Error: detail})
			seen[result.InstanceID] = true
		}
		return review, nil
	}
	err := postLifecycleUpdate(outputOpts, client, pathf("/api/containers/projects/%s/update", projectID), body, &response, projectUpdateOpts.projectUpdateYes, "project update", replan)
	response.Results = append(response.Results, excluded...)
	return response, err
}

func preserveProjectCounts(updated, current projectView) projectView {
	updated.InstanceCount = current.InstanceCount
	updated.RunningCount = current.RunningCount
	updated.FailedCount = current.FailedCount
	updated.StoppedCount = current.StoppedCount
	updated.DeployingCount = current.DeployingCount
	return updated
}

func renderProject(outputOpts *outputOptions, project projectView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(project)
	}
	fmt.Printf("ID:              %s\n", project.ID)
	fmt.Printf("Repository:      %s\n", project.Repo)
	fmt.Printf("Instances:       %d\n", project.InstanceCount)
	fmt.Printf("Running:         %d\n", project.RunningCount)
	fmt.Printf("Deploying:       %d\n", project.DeployingCount)
	fmt.Printf("Failed:          %d\n", project.FailedCount)
	fmt.Printf("Stopped:         %d\n", project.StoppedCount)
	fmt.Printf("Default hold: %v\n", project.HoldByDefault)
	return nil
}

func renderProjects(outputOpts *outputOptions, projects []projectView) error {
	if outputOpts.outputFormat == "json" {
		return printJSON(projects)
	}
	if len(projects) == 0 {
		fmt.Println("No projects.")
		return nil
	}
	fmt.Printf("%-36s  %-9s  %-7s  %-11s  %s\n",
		"REPOSITORY", "INSTANCES", "RUNNING", "DEPLOYING", "FAILED",
	)
	for _, project := range projects {
		fmt.Printf("%-36s  %-9d  %-7d  %-11d  %d\n",
			truncate(project.Repo, 36),
			project.InstanceCount,
			project.RunningCount,
			project.DeployingCount,
			project.FailedCount,
		)
	}
	return nil
}

func renderProjectUpdateResults(outputOpts *outputOptions, results []projectInstanceResult) error {
	if outputOpts.outputFormat == "json" {
		if err := printJSON(projectUpdateResponse{Results: results}); err != nil {
			return err
		}
	}
	if len(results) == 0 {
		if outputOpts.outputFormat != "json" {
			fmt.Println("No project instances were selected.")
		}
		return nil
	}
	if outputOpts.outputFormat != "json" {
		fmt.Printf("%-24s  %-10s  %s\n", "NAME", "STATUS", "DETAIL")
	}
	failed, skipped := 0, 0
	for _, result := range results {
		if outputOpts.outputFormat != "json" {
			detail := humanVolumeMessage(secretDeliveryMessage(result.Error))
			if detail == "" {
				detail = result.ContainerID
			}
			fmt.Printf("%-24s  %-10s  %s\n", truncate(result.Name, 24), result.Status, detail)
		}
		switch result.Status {
		case projectInstanceStatusFailed:
			failed++
		case projectInstanceStatusSkipped:
			skipped++
		}
	}
	if failed > 0 || skipped > 0 {
		return fmt.Errorf("project update incomplete: %d failed, %d skipped", failed, skipped)
	}
	return nil
}
