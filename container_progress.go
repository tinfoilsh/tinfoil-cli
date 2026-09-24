package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// Container statuses as the controlplane reports them.
const (
	statusCreated   = "created"
	statusPending   = "pending"
	statusDeploying = "deploying"
	statusStarted   = "started"
	statusRunning   = "running"
	statusFailed    = "failed"
	statusStopping  = "stopping"
	statusStopped   = "stopped"

	// Update candidates keep tinfoild's vocabulary, where a candidate that
	// passed its boot checks is "ready".
	updateStatusReady = "ready"

	updateStrategyReplace        = "replace"
	updateTypeQueuedDeploy       = "queued_deploy"
	downtimeConfirmationRequired = "DOWNTIME_CONFIRMATION_REQUIRED"

	followTimeout = 30 * time.Minute
)

// followInterval is how often followContainer polls. A variable so tests can
// shorten it.
var followInterval = 2 * time.Second

// statusLabel is the status as shown to users: the API value in sentence
// case, with "started" spelled out as the health-check phase it is.
func statusLabel(status string) string {
	switch status {
	case statusStarted:
		return "Starting"
	case "":
		return "-"
	}
	return strings.ToUpper(status[:1]) + status[1:]
}

// updateLabel describes an in-flight update candidate in one phrase.
func updateLabel(c containerView) string {
	switch c.UpdateStatus {
	case updateStatusReady:
		if heldCandidateReady(c) {
			return "held for review; promote to switch traffic"
		}
		return "switching traffic"
	case statusFailed:
		return "failed"
	}
	if stage := activeBootStage(c.UpdateBootStages); stage != "" {
		return strings.ToLower(statusLabel(c.UpdateStatus)) + ": " + stage
	}
	return strings.ToLower(statusLabel(c.UpdateStatus))
}

// replaceReason names why an update must replace the running instance.
func replaceReason(c containerView) string {
	if c.GPUs > 1 {
		return fmt.Sprintf("it uses %d GPUs", c.GPUs)
	}
	return "it has persistent volumes"
}

func postLifecycleUpdate(client *cpClient, path string, body map[string]any, out any, yes bool, action string, replan func() (updateReview, error)) error {
	delete(body, "confirm_downtime")
	review, err := replan()
	if err != nil {
		return err
	}
	changed, retried := false, false
	for range maxUpdatePlanReviews {
		if err := review.render(); err != nil {
			return err
		}
		if err := review.freezeSelection(body); err != nil {
			return err
		}
		if err := confirmUpdatePlans(review.plans, yes, action, changed); err != nil {
			return err
		}
		next, err := replan()
		if err != nil {
			return err
		}
		if !sameUpdateReview(review, next) {
			review, changed = next, true
			continue
		}
		if review.requiresDowntime() {
			body["confirm_downtime"] = true
		}
		_, err = client.do("POST", path, nil, body, out)
		if !needsDowntimeReplan(err) || retried || body["confirm_downtime"] == true {
			return err
		}
		delete(body, "confirm_downtime")
		refreshed, planErr := replan()
		if planErr != nil {
			return planErr
		}
		if !refreshed.requiresDowntime() {
			if printErr := refreshed.render(); printErr != nil {
				return printErr
			}
			return fmt.Errorf("execution requires downtime but the refreshed plan does not; no retry was sent: %w", err)
		}
		// The retry must pass through the same review and post-consent recheck.
		review = refreshed
		changed, retried = true, true
	}
	if err := review.render(); err != nil {
		return err
	}
	return fmt.Errorf("update plan did not stabilize after %d reviews; no further update was sent; rerun to review current settings", maxUpdatePlanReviews)
}

func needsDowntimeReplan(err error) bool {
	var cp *cpError
	if !errors.As(err, &cp) || cp.Status != http.StatusConflict {
		return false
	}
	var detail struct {
		Code string `json:"code"`
	}
	return json.Unmarshal(cp.Body, &detail) == nil && detail.Code == downtimeConfirmationRequired
}

// activeBootStage returns the name of the first stage still in progress.
func activeBootStage(stages []bootStage) string {
	for _, stage := range stages {
		if nested := activeBootStage(stage.Stages); nested != "" {
			return nested
		}
		if stage.Status == "pending" || stage.Status == "running" {
			return stage.Name
		}
	}
	return ""
}

// followAndRender prints the container, then follows its progress until it
// reaches a terminal state, printing each change the way the dashboard shows
// it. JSON output and --no-wait print the initial response only. Exits
// non-zero when the container or its update candidate fails.
func followAndRender(client *cpClient, c containerView, attached map[string]volumeView) error {
	if err := renderContainerDetail(c, attached); err != nil {
		return err
	}
	if outputFormat != "json" && !noWait && !isTerminal(c) {
		final, err := followContainer(client, c.ID, c)
		if err == nil {
			printChangedContainerConnections(os.Stdout, c, final)
		}
		return err
	}
	return failureError(c)
}

// failureError turns a failed container or update candidate into a non-zero
// exit, whether the failure was in the initial response or observed while
// following.
func failureError(c containerView) error {
	if c.Status != statusFailed && c.UpdateStatus != statusFailed {
		return nil
	}
	msg := c.ErrorMessage
	if msg == "" {
		msg = "deployment failed; run \"tinfoil container get " + c.Name + "\" for details"
	}
	return fmt.Errorf("%s", humanVolumeMessage(msg))
}

// isTerminal reports whether there is nothing left to follow for c. A
// lifecycle command only returns a stopped container transiently (a deploy
// queued behind a stop), so stopped is not terminal here.
func isTerminal(c containerView) bool {
	if c.UpdateDeploymentID != "" || c.UpdateTag != "" {
		return c.UpdateStatus == statusFailed || heldCandidateReady(c)
	}
	switch c.Status {
	case statusRunning, statusFailed:
		return true
	}
	return false
}

func heldCandidateReady(c containerView) bool {
	return c.UpdateStatus == updateStatusReady && c.candidateHeld() &&
		c.UpdateType != updateTypeQueuedDeploy && c.UpdateType != updateStrategyReplace
}

func followedDeploymentState(c containerView, deploymentID string) (bool, error) {
	if c.TinfoildDeploymentID == deploymentID && c.Status == statusRunning {
		return true, nil
	}
	if c.UpdateDeploymentID == deploymentID {
		if c.UpdateStatus == statusFailed {
			return true, failureError(c)
		}
		if c.UpdateStatus == statusStopped || c.UpdateStatus == statusStopping {
			return true, fmt.Errorf("deployment %s on %s was stopped before completion", deploymentID, c.Name)
		}
		return heldCandidateReady(c), nil
	}
	if c.TinfoildDeploymentID != deploymentID || c.UpdateDeploymentID != "" {
		return true, fmt.Errorf("deployment %s on %s was canceled or superseded; check \"tinfoil container get %s\"", deploymentID, c.Name, c.ID)
	}
	if c.Status == statusStopped || c.Status == statusStopping {
		return true, fmt.Errorf("deployment %s on %s was stopped before completion", deploymentID, c.Name)
	}
	return isTerminal(c), failureError(c)
}

// followContainer polls the container until isTerminal, printing one line per
// observed change. The last line is left in place; intermediate lines are
// overwritten when stderr is a terminal.
func followContainer(client *cpClient, id string, initial containerView) (containerView, error) {
	deploymentID := initial.UpdateDeploymentID
	if deploymentID == "" && initial.UpdateTag == "" && initial.UpdateType == "" {
		deploymentID = initial.TinfoildDeploymentID
	}
	if deploymentID == "" {
		return initial, fmt.Errorf("cannot follow %s: response has no deployment ID; check \"tinfoil container get %s\"", initial.Name, id)
	}
	tty := term.IsTerminal(int(os.Stderr.Fd()))
	last := ""
	print := func(line string) {
		if line == last {
			return
		}
		if tty && last != "" {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		fmt.Fprint(os.Stderr, line)
		if !tty {
			fmt.Fprintln(os.Stderr)
		}
		last = line
	}
	finish := func() {
		if tty && last != "" {
			fmt.Fprintln(os.Stderr)
		}
	}
	defer finish()

	current := initial
	deadline := time.Now().Add(followTimeout)
	for {
		done, err := followedDeploymentState(current, deploymentID)
		if err != nil {
			return current, err
		}
		display := current
		if current.TinfoildDeploymentID == deploymentID {
			display.UpdateTag = ""
		}
		print(progressLine(display))
		if done {
			return current, nil
		}
		if time.Now().After(deadline) {
			return current, fmt.Errorf("still %s after %s; check \"tinfoil container get %s\"", strings.ToLower(statusLabel(current.Status)), followTimeout, current.Name)
		}
		time.Sleep(followInterval)
		var next containerView
		if _, err := client.do("GET", pathf("/api/containers/%s", id), nil, nil, &next); err != nil {
			return current, err
		}
		current = next
	}
}

// progressLine is the single line shown while following a container.
func progressLine(c containerView) string {
	if c.UpdateTag != "" {
		return fmt.Sprintf("Update to %s: %s", c.UpdateTag, updateLabel(c))
	}
	label := statusLabel(c.Status)
	if stage := activeBootStage(c.BootStages); stage != "" && c.Status != statusRunning {
		return fmt.Sprintf("%s: %s", label, stage)
	}
	if c.Status == statusRunning && c.Domain != "" {
		return fmt.Sprintf("%s at https://%s", label, c.Domain)
	}
	return label
}
