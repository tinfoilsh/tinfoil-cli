package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	updateStrategyBlueGreen = "blue_green"
	planStatusPlanned       = "planned"
)

type plannedResources struct {
	Tag      string `json:"tag"`
	CPUs     int    `json:"cpus"`
	MemoryMB *int   `json:"memory_mb"`
	GPUs     int    `json:"gpus"`
}

type plannedNameChanges struct {
	Added   []string `json:"added"`
	Changed []string `json:"changed"`
	Removed []string `json:"removed"`
}

type updatePlan struct {
	ReadOnly             bool             `json:"read_only"`
	InstanceID           string           `json:"instance_id"`
	Name                 string           `json:"name"`
	Current              plannedResources `json:"current"`
	Target               plannedResources `json:"target"`
	UpdateStrategy       string           `json:"update_strategy"`
	DowntimeRequired     bool             `json:"downtime_required"`
	Hold                 bool             `json:"hold"`
	HoldSource           string           `json:"hold_source"`
	HoldAvailable        bool             `json:"hold_available"`
	MarkLatestRelease    bool             `json:"mark_latest_release"`
	ConfigurationChanges struct {
		Variables        plannedNameChanges `json:"variables"`
		Secrets          plannedNameChanges `json:"secrets"`
		SSHKeys          plannedNameChanges `json:"ssh_keys"`
		Settings         []string           `json:"settings"`
		SecretsRefreshed []string           `json:"secrets_refreshed"`
	} `json:"configuration_changes"`
	VolumeData   string `json:"volume_data"`
	CostEstimate struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	} `json:"cost_estimate"`
}

type projectUpdatePlan struct {
	ReadOnly         bool   `json:"read_only"`
	ProjectID        string `json:"project_id"`
	LatestReleaseTag string `json:"latest_release_tag"`
	EligibleCount    int    `json:"eligible_count"`
	SkippedCount     int    `json:"skipped_count"`
	FailedCount      int    `json:"failed_count"`
	Results          []struct {
		InstanceID string      `json:"instance_id"`
		Name       string      `json:"name"`
		Status     string      `json:"status"`
		Plan       *updatePlan `json:"plan"`
		Error      *string     `json:"error"`
	} `json:"results"`
}

func (plan updatePlan) validate(id string) error {
	if !plan.ReadOnly || plan.InstanceID != id || plan.Target.Tag == "" ||
		(plan.UpdateStrategy != updateStrategyBlueGreen && plan.UpdateStrategy != updateStrategyReplace) ||
		(plan.HoldSource != "project" && plan.HoldSource != "request") ||
		plan.DowntimeRequired != (plan.UpdateStrategy == updateStrategyReplace) {
		return fmt.Errorf("invalid update plan response; no update was sent")
	}
	return nil
}

func planContainerUpdate(client *cpClient, id string, body map[string]any) (updatePlan, error) {
	var plan updatePlan
	if _, err := client.do("POST", pathf("/api/containers/%s/update/plan", id), nil, body, &plan); err != nil {
		return plan, fmt.Errorf("could not plan update; no update was sent: %w", err)
	}
	if err := plan.validate(id); err != nil {
		return plan, err
	}
	if outputFormat == "json" {
		if err := json.NewEncoder(os.Stderr).Encode(plan); err != nil {
			return plan, err
		}
	} else {
		renderUpdatePlan(os.Stderr, plan)
	}
	return plan, nil
}

func planProjectUpdate(client *cpClient, id string, body map[string]any) ([]updatePlan, error) {
	var response projectUpdatePlan
	if _, err := client.do("POST", pathf("/api/containers/projects/%s/update/plan", id), nil, body, &response); err != nil {
		return nil, fmt.Errorf("could not plan project update; no update was sent: %w", err)
	}
	if !response.ReadOnly || response.ProjectID != id {
		return nil, fmt.Errorf("invalid project update plan response; no update was sent")
	}
	var plans []updatePlan
	for _, result := range response.Results {
		if result.Status == planStatusPlanned {
			if result.Plan == nil {
				return nil, fmt.Errorf("missing instance plan; no update was sent")
			}
			if err := result.Plan.validate(result.InstanceID); err != nil {
				return nil, err
			}
			plans = append(plans, *result.Plan)
		} else if result.Status != projectInstanceStatusSkipped && result.Status != projectInstanceStatusFailed {
			return nil, fmt.Errorf("invalid project plan result status; no update was sent")
		}
	}
	if len(plans) != response.EligibleCount || len(response.Results) != response.EligibleCount+response.SkippedCount+response.FailedCount {
		return nil, fmt.Errorf("inconsistent project plan counts; no update was sent")
	}
	if outputFormat == "json" {
		if err := json.NewEncoder(os.Stderr).Encode(response); err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintf(os.Stderr, "Project plan (read-only): %d eligible, %d skipped, %d failed\n", response.EligibleCount, response.SkippedCount, response.FailedCount)
		fmt.Fprintf(os.Stderr, "GitHub latest release: %s\n", displayNames([]string{response.LatestReleaseTag}))
		for _, result := range response.Results {
			if result.Plan != nil {
				renderUpdatePlan(os.Stderr, *result.Plan)
			} else {
				detail := ""
				if result.Error != nil {
					detail = *result.Error
				}
				fmt.Fprintf(os.Stderr, "%s (%s): %s %s\n", result.Name, result.InstanceID, result.Status, detail)
			}
		}
	}
	if response.FailedCount > 0 || len(plans) == 0 {
		return nil, fmt.Errorf("project plan cannot proceed: %d failed, %d eligible; no update was sent", response.FailedCount, len(plans))
	}
	return plans, nil
}

func renderUpdatePlan(out io.Writer, plan updatePlan) {
	fmt.Fprintf(out, "Update plan (read-only): %s (%s)\n", plan.Name, plan.InstanceID)
	fmt.Fprintf(out, "  Tag: %s -> %s\n  CPU: %d -> %d; RAM (MB): %s -> %s; GPU: %d -> %d\n", plan.Current.Tag, plan.Target.Tag, plan.Current.CPUs, plan.Target.CPUs, plannedMemory(plan.Current.MemoryMB), plannedMemory(plan.Target.MemoryMB), plan.Current.GPUs, plan.Target.GPUs)
	fmt.Fprintf(out, "  Strategy: %s; downtime: %t\n  Hold: %t (source: %s; available: %t)\n  Volume data: %s\n", plan.UpdateStrategy, plan.DowntimeRequired, plan.Hold, plan.HoldSource, plan.HoldAvailable, plan.VolumeData)
	fmt.Fprintln(out, "  Uses current settings and current secret values, not a historical snapshot; values are not displayed.")
	for _, change := range []struct {
		label string
		names plannedNameChanges
	}{{"Variables", plan.ConfigurationChanges.Variables}, {"Secrets", plan.ConfigurationChanges.Secrets}, {"SSH keys", plan.ConfigurationChanges.SSHKeys}} {
		fmt.Fprintf(out, "  %s: added [%s], changed [%s], removed [%s]\n", change.label, displayNames(change.names.Added), displayNames(change.names.Changed), displayNames(change.names.Removed))
	}
	fmt.Fprintf(out, "  Changed settings: %s\n  Refresh current secret values: %s\n", displayNames(plan.ConfigurationChanges.Settings), displayNames(plan.ConfigurationChanges.SecretsRefreshed))
	fmt.Fprintf(out, "  Mark GitHub latest: %t\n", plan.MarkLatestRelease)
	if plan.MarkLatestRelease {
		fmt.Fprintln(out, "  WARNING: marking latest affects the repository-wide latest release and other consumers, even when selecting an earlier release. Use --mark-latest=false to leave it unchanged.")
	}
	reason := plan.CostEstimate.Reason
	if reason == "" {
		reason = "the server did not provide a usable estimate"
	}
	fmt.Fprintf(out, "  Estimated cost: not available (%s)\n", reason)
}

func displayNames(names []string) string {
	if len(names) == 0 || len(names) == 1 && names[0] == "" {
		return "none"
	}
	return strings.Join(names, ", ")
}

func plannedMemory(memory *int) string {
	if memory == nil {
		return "not available"
	}
	return fmt.Sprint(*memory)
}

func confirmUpdatePlans(plans []updatePlan, body map[string]any, yes bool, action string) error {
	var downtime []string
	for _, plan := range plans {
		if plan.Hold && !plan.HoldAvailable {
			return fmt.Errorf("holding for review is not available for %s (strategy: %s; hold source: %s); pass --hold=false or select other instances", plan.Name, plan.UpdateStrategy, plan.HoldSource)
		}
		if plan.DowntimeRequired {
			downtime = append(downtime, plan.Name)
		}
	}
	if len(downtime) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "This update will cause downtime for: %s. Each instance is unreachable until its replacement is Running.\n", strings.Join(downtime, ", "))
	if err := confirmYes(yes, action); err != nil {
		return err
	}
	body["confirm_downtime"] = true
	return nil
}
