package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Finish each step before starting another or prompting for credentials.
// Waiting for the reporter to exit keeps stale messages out of the next step.
func startConnectionProgress(out io.Writer, message string) func() {
	fmt.Fprintf(out, "%s...\n", message)
	started := time.Now()
	ticker := time.NewTicker(10 * time.Second)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fmt.Fprintf(out, "%s... %s elapsed\n", message, time.Since(started).Truncate(time.Second))
			}
		}
	}()
	return sync.OnceFunc(func() { close(stop); <-done })
}

func requireRunningConnection(kind string, row containerView) error {
	if row.Status == statusRunning {
		return nil
	}
	var next string
	switch row.Status {
	case "created":
		next = "configuration is still being prepared and published; retry when provisioning finishes"
	case "pending", "deploying", "started":
		next = "provisioning is still in progress; retry when it is running"
	case "stopping":
		next = "wait for it to stop, then start it before connecting"
	case "stopped":
		next = "start it before connecting"
	case "failed":
		next = "check the deployment error in the dashboard before restarting it"
	default:
		next = "check its status in the dashboard before connecting"
	}
	return fmt.Errorf("%s %s is %s; %s", kind, row.Name, statusLabel(row.Status), next)
}
