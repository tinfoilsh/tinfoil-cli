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
		if c.candidateHeld() {
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

// confirmDowntime explains that an update will take the container offline and
// requires the user to type yes, unless --yes was given.
func confirmDowntime(c containerView) error {
	fmt.Fprintf(os.Stderr, "Updating %s will cause downtime.\n\n", c.Name)
	fmt.Fprintf(os.Stderr, "This container %s, so the new version cannot run alongside the current one.\n", replaceReason(c))
	fmt.Fprintln(os.Stderr, "The running instance is stopped first and the new version deploys in its place.")
	fmt.Fprintln(os.Stderr, "It will be unreachable until the new version is Running.")
	fmt.Fprintln(os.Stderr)
	return confirmYes(updateYes, "container update")
}

func postLifecycleUpdate(client *cpClient, path string, body map[string]any, out any, yes bool, action string, instances []string) error {
	_, err := client.do("POST", path, nil, body, out)
	var cp *cpError
	if !errors.As(err, &cp) || cp.Status != http.StatusConflict || body["confirm_downtime"] == true {
		return err
	}
	var detail struct {
		Code      string   `json:"code"`
		Instances []string `json:"instances"`
	}
	if json.Unmarshal(cp.Body, &detail) != nil || detail.Code != downtimeConfirmationRequired {
		return err
	}
	if len(detail.Instances) > 0 {
		instances = detail.Instances
	}
	fmt.Fprintln(os.Stderr, "This update will cause downtime for:")
	for _, name := range instances {
		fmt.Fprintf(os.Stderr, "  %s\n", name)
	}
	fmt.Fprintln(os.Stderr, "The target configuration requires replacement: each running instance stops first and")
	fmt.Fprintln(os.Stderr, "is unreachable until its new version is Running.")
	if err := confirmYes(yes, action); err != nil {
		return err
	}
	body["confirm_downtime"] = true
	_, err = client.do("POST", path, nil, body, out)
	return err
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
	final := c
	if outputFormat != "json" && !noWait && !isTerminal(c) {
		var err error
		if final, err = followContainer(client, c.ID, c); err != nil {
			return err
		}
	}
	return failureError(final)
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
	return fmt.Errorf("%s", msg)
}

// isTerminal reports whether there is nothing left to follow for c. A
// lifecycle command only returns a stopped container transiently (a deploy
// queued behind a stop), so stopped is not terminal here.
func isTerminal(c containerView) bool {
	if c.UpdateTag != "" {
		return c.UpdateStatus == statusFailed || (c.UpdateStatus == updateStatusReady && c.candidateHeld())
	}
	switch c.Status {
	case statusRunning, statusFailed:
		return true
	}
	return false
}

// followContainer polls the container until isTerminal, printing one line per
// observed change. The last line is left in place; intermediate lines are
// overwritten when stderr is a terminal.
func followContainer(client *cpClient, id string, initial containerView) (containerView, error) {
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

	current := initial
	deadline := time.Now().Add(followTimeout)
	print(progressLine(current))
	for !isTerminal(current) {
		if time.Now().After(deadline) {
			finish()
			return current, fmt.Errorf("still %s after %s; check \"tinfoil container get %s\"", strings.ToLower(statusLabel(current.Status)), followTimeout, current.Name)
		}
		time.Sleep(followInterval)
		var next containerView
		if _, err := client.do("GET", pathf("/api/containers/%s", id), nil, nil, &next); err != nil {
			finish()
			return current, err
		}
		current = next
		print(progressLine(current))
	}
	finish()
	return current, nil
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
