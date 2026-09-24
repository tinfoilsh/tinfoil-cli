package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
)

const (
	updateStrategyBlueGreen = "blue_green"
	planStatusPlanned       = "planned"
	maxUpdatePlanReviews    = 3
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
	SecretDelivery *plannedSecretDelivery `json:"secret_delivery,omitempty"`
	VolumeData     string                 `json:"volume_data"`
	CostEstimate   struct {
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
	if plan.SecretDelivery != nil {
		return plan.SecretDelivery.validate(plan.ConfigurationChanges.SecretsRefreshed)
	}
	return nil
}

type updateReview struct {
	plans   []updatePlan
	project *projectUpdatePlan
}

func planContainerUpdate(client *cpClient, id string, body map[string]any) (updateReview, error) {
	var plan updatePlan
	if _, err := client.do("POST", pathf("/api/containers/%s/update/plan", id), nil, body, &plan); err != nil {
		return updateReview{}, fmt.Errorf("could not plan update; no update was sent: %w", err)
	}
	if err := plan.validate(id); err != nil {
		return updateReview{}, err
	}
	return updateReview{plans: []updatePlan{plan}}, nil
}

func planProjectUpdate(client *cpClient, id string, body map[string]any) (updateReview, error) {
	var response projectUpdatePlan
	if _, err := client.do("POST", pathf("/api/containers/projects/%s/update/plan", id), nil, body, &response); err != nil {
		return updateReview{}, fmt.Errorf("could not plan project update; no update was sent: %w", err)
	}
	if !response.ReadOnly || response.ProjectID != id {
		return updateReview{}, fmt.Errorf("invalid project update plan response; no update was sent")
	}
	var plans []updatePlan
	selected, restricted := body["instance_ids"].([]string)
	seen := make(map[string]bool)
	skipped, failed := 0, 0
	for _, result := range response.Results {
		if result.InstanceID == "" || seen[result.InstanceID] || restricted && !slices.Contains(selected, result.InstanceID) {
			return updateReview{}, fmt.Errorf("project plan returned duplicate or unselected instances; no update was sent")
		}
		seen[result.InstanceID] = true
		if result.Status == planStatusPlanned {
			if result.Plan == nil {
				return updateReview{}, fmt.Errorf("missing instance plan; no update was sent")
			}
			if err := result.Plan.validate(result.InstanceID); err != nil {
				return updateReview{}, err
			}
			plans = append(plans, *result.Plan)
		} else {
			if result.Plan != nil {
				return updateReview{}, fmt.Errorf("noneligible instance has a plan; no update was sent")
			}
			switch result.Status {
			case projectInstanceStatusSkipped:
				skipped++
			case projectInstanceStatusFailed:
				failed++
			default:
				return updateReview{}, fmt.Errorf("invalid project plan result status; no update was sent")
			}
		}
	}
	for _, id := range selected {
		if !seen[id] {
			return updateReview{}, fmt.Errorf("project plan omitted selected instance %s; no update was sent", id)
		}
	}
	if len(plans) != response.EligibleCount || skipped != response.SkippedCount || failed != response.FailedCount {
		return updateReview{}, fmt.Errorf("inconsistent project plan counts; no update was sent")
	}
	return updateReview{plans: plans, project: &response}, nil
}

func (review updateReview) render() error {
	if outputFormat == "json" {
		if review.project != nil {
			return json.NewEncoder(os.Stderr).Encode(review.project)
		}
		return json.NewEncoder(os.Stderr).Encode(review.plans[0])
	}
	if response := review.project; response != nil {
		fmt.Fprintf(os.Stderr, "Project plan (read-only): %d eligible, %d skipped, %d failed\n", response.EligibleCount, response.SkippedCount, response.FailedCount)
		fmt.Fprintf(os.Stderr, "GitHub latest release: %s\n", displayNames([]string{response.LatestReleaseTag}))
		for _, result := range response.Results {
			if result.Plan != nil {
				renderUpdatePlan(os.Stderr, *result.Plan)
			} else {
				detail := ""
				if result.Error != nil {
					detail = secretDeliveryMessage(*result.Error)
				}
				fmt.Fprintf(os.Stderr, "%s (%s): %s %s\n", result.Name, result.InstanceID, result.Status, detail)
			}
		}
	} else {
		renderUpdatePlan(os.Stderr, review.plans[0])
	}
	return nil
}

func (review updateReview) freezeSelection(body map[string]any) error {
	if review.project == nil {
		return nil
	}
	if review.project.FailedCount > 0 || len(review.plans) == 0 {
		return fmt.Errorf("project plan cannot proceed: %d failed, %d eligible; no update was sent", review.project.FailedCount, len(review.plans))
	}
	ids := make([]string, 0, len(review.plans))
	for _, plan := range review.plans {
		ids = append(ids, plan.InstanceID)
	}
	slices.Sort(ids)
	body["instance_ids"] = ids
	return nil
}

func (review updateReview) requiresDowntime() bool {
	for _, plan := range review.plans {
		if plan.DowntimeRequired {
			return true
		}
	}
	return false
}

func sameUpdateReview(a, b updateReview) bool {
	if a.project != nil && b.project != nil && a.project.LatestReleaseTag != b.project.LatestReleaseTag {
		return false
	}
	if (a.project == nil) != (b.project == nil) {
		return false
	}
	return reflect.DeepEqual(reviewedPlans(a.plans), reviewedPlans(b.plans))
}

func reviewedPlans(plans []updatePlan) map[string]updatePlan {
	result := make(map[string]updatePlan, len(plans))
	for _, plan := range plans {
		changes := &plan.ConfigurationChanges
		for _, names := range []*plannedNameChanges{&changes.Variables, &changes.Secrets, &changes.SSHKeys} {
			names.Added = sortedPlanNames(names.Added)
			names.Changed = sortedPlanNames(names.Changed)
			names.Removed = sortedPlanNames(names.Removed)
		}
		changes.Settings = sortedPlanNames(changes.Settings)
		changes.SecretsRefreshed = sortedPlanNames(changes.SecretsRefreshed)
		plan.SecretDelivery = plan.reviewedSecretDelivery()
		result[plan.InstanceID] = plan
	}
	return result
}

func sortedPlanNames(names []string) []string {
	result := append([]string{}, names...)
	slices.Sort(result)
	return result
}

func renderUpdatePlan(out io.Writer, plan updatePlan) {
	fmt.Fprintf(out, "Update plan (read-only): %s (%s)\n", plan.Name, plan.InstanceID)
	fmt.Fprintf(out, "  Tag: %s -> %s\n  CPU: %d -> %d; RAM (MB): %s -> %s; GPU: %d -> %d\n", plan.Current.Tag, plan.Target.Tag, plan.Current.CPUs, plan.Target.CPUs, plannedMemory(plan.Current.MemoryMB), plannedMemory(plan.Target.MemoryMB), plan.Current.GPUs, plan.Target.GPUs)
	fmt.Fprintf(out, "  Strategy: %s; downtime: %t\n  Hold: %t (source: %s; available: %t)\n  Volume data: %s\n", plan.UpdateStrategy, plan.DowntimeRequired, plan.Hold, plan.HoldSource, plan.HoldAvailable, plan.VolumeData)
	if plan.SecretDelivery != nil && plan.SecretDelivery.Mode == secretDeliveryPrivateKeyserver {
		fmt.Fprintln(out, "  Uses current settings, not a historical snapshot; private secret values are fetched by the guest and are not displayed.")
	} else {
		fmt.Fprintln(out, "  Uses current settings and current secret values, not a historical snapshot; values are not displayed.")
	}
	for _, change := range []struct {
		label string
		names plannedNameChanges
	}{{"Variables", plan.ConfigurationChanges.Variables}, {"Secrets", plan.ConfigurationChanges.Secrets}, {"SSH keys", plan.ConfigurationChanges.SSHKeys}} {
		if change.label == "Secrets" && plan.SecretDelivery != nil {
			change.label = "Managed secret changes"
		}
		fmt.Fprintf(out, "  %s: added [%s], changed [%s], removed [%s]\n", change.label, displayNames(change.names.Added), displayNames(change.names.Changed), displayNames(change.names.Removed))
	}
	fmt.Fprintf(out, "  Changed settings: %s\n", displayNames(plan.ConfigurationChanges.Settings))
	if plan.SecretDelivery != nil {
		plan.SecretDelivery.render(out)
	} else {
		fmt.Fprintf(out, "  Refresh current secret values: %s\n", displayNames(plan.ConfigurationChanges.SecretsRefreshed))
	}
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

func confirmUpdatePlans(plans []updatePlan, yes bool, action string, changed bool) error {
	var downtime []string
	for _, plan := range plans {
		if plan.Hold && !plan.HoldAvailable {
			return fmt.Errorf("holding for review is not available for %s (strategy: %s; hold source: %s); pass --hold=false or select other instances", plan.Name, plan.UpdateStrategy, plan.HoldSource)
		}
		if plan.DowntimeRequired {
			downtime = append(downtime, plan.Name)
		}
	}
	if len(downtime) == 0 && !changed {
		return nil
	}
	if changed {
		fmt.Fprintln(os.Stderr, "The reviewed update changed; fresh confirmation is required.")
	}
	if len(downtime) > 0 {
		fmt.Fprintf(os.Stderr, "This update will cause downtime for: %s. Each instance is unreachable until its replacement is Running.\n", strings.Join(downtime, ", "))
	}
	if yes {
		fmt.Fprintln(os.Stderr, "Accepting the displayed update plan automatically (--yes).")
		return nil
	}
	return confirmYes(false, action)
}
