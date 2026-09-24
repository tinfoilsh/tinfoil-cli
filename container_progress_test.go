package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatusLabelIsSentenceCaseAPIValue(t *testing.T) {
	for status, want := range map[string]string{
		statusRunning:   "Running",
		statusDeploying: "Deploying",
		statusStarted:   "Starting",
		statusFailed:    "Failed",
		"":              "-",
	} {
		if got := statusLabel(status); got != want {
			t.Errorf("statusLabel(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestUpdateLabelDistinguishesHeldFromAutoSwitch(t *testing.T) {
	held := containerView{UpdateTag: "v2", UpdateStatus: updateStatusReady, Held: true}
	if got := updateLabel(held); got != "held for review; promote to switch traffic" {
		t.Fatalf("held label = %q", got)
	}
	auto := containerView{UpdateTag: "v2", UpdateStatus: updateStatusReady}
	if got := updateLabel(auto); got != "switching traffic" {
		t.Fatalf("auto label = %q", got)
	}
	booting := containerView{UpdateTag: "v2", UpdateStatus: statusDeploying, UpdateBootStages: []bootStage{
		{Name: "pull image", Status: "completed"},
		{Name: "start workload", Status: "running"},
	}}
	if got := updateLabel(booting); got != "deploying: start workload" {
		t.Fatalf("booting label = %q", got)
	}
}

func TestFollowContainerStopsAtTerminalStateAndFailsOnFailed(t *testing.T) {
	previousInterval := followInterval
	followInterval = time.Millisecond
	t.Cleanup(func() { followInterval = previousInterval })

	var polls atomic.Int32
	statuses := []string{statusDeploying, statusStarted, statusFailed}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(polls.Add(1)) - 1
		if n >= len(statuses) {
			n = len(statuses) - 1
		}
		_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","tinfoild_deployment_id":"deploy-1","status":"`+statuses[n]+`","error_message":"health check failed"}`)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	noWait, outputFormat = false, "table"

	client, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = captureTestStdout(func() error {
		return followAndRender(client, containerView{ID: testContainerID, Name: "app", Status: statusPending, TinfoildDeploymentID: "deploy-1"}, nil)
	})
	if err == nil || err.Error() != "health check failed" {
		t.Fatalf("error = %v, want the container's error message", err)
	}
	if got := polls.Load(); got != int32(len(statuses)) {
		t.Fatalf("polls = %d, want %d (one per status until failed)", got, len(statuses))
	}
}

func TestFollowAndRenderExitsNonZeroWhenInitialResponseAlreadyFailed(t *testing.T) {
	previousNoWait, previousOutput := noWait, outputFormat
	t.Cleanup(func() { noWait, outputFormat = previousNoWait, previousOutput })
	for _, mode := range []struct {
		name   string
		noWait bool
		format string
	}{{"json", false, "json"}, {"no-wait", true, "table"}, {"follow", false, "table"}} {
		t.Run(mode.name, func(t *testing.T) {
			noWait, outputFormat = mode.noWait, mode.format
			_, err := captureTestStdout(func() error {
				return followAndRender(nil, containerView{ID: testContainerID, Name: "app", Status: statusFailed, ErrorMessage: "boot failed"}, nil)
			})
			if err == nil || err.Error() != "boot failed" {
				t.Fatalf("error = %v, want the container's error message", err)
			}
		})
	}
}

func TestIsTerminalHoldsForStagedCandidateAndStopsForRunning(t *testing.T) {
	if !isTerminal(containerView{Status: statusRunning}) {
		t.Fatal("running container should be terminal")
	}
	if isTerminal(containerView{Status: statusStopped}) {
		t.Fatal("stopped is transient while a queued deploy waits; keep following")
	}
	if isTerminal(containerView{Status: statusStopping}) {
		t.Fatal("stopping container should keep being followed")
	}
	if isTerminal(containerView{Status: statusRunning, UpdateTag: "v2", UpdateStatus: statusDeploying}) {
		t.Fatal("container with a booting candidate should not be terminal")
	}
	if !isTerminal(containerView{Status: statusRunning, UpdateTag: "v2", UpdateStatus: updateStatusReady, Held: true}) {
		t.Fatal("held ready candidate should be terminal (waits for promote)")
	}
	if isTerminal(containerView{Status: statusRunning, UpdateTag: "v2", UpdateStatus: updateStatusReady}) {
		t.Fatal("auto-switching candidate should not be terminal until promoted")
	}
}

func TestContainerUpdateRefusesHoldOnReplaceStrategyLocally(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
			_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"running","gpus":8,"update_strategy":"replace"}`)
		case r.Method == http.MethodPost:
			posts.Add(1)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	updateHold = "true"
	containerUpdateCmd.Flags().Lookup("hold").Changed = true

	_, err := captureTestStdout(func() error {
		return containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID})
	})
	if err == nil || !strings.Contains(err.Error(), "holding for review is not available for app: it uses 8 GPUs") {
		t.Fatalf("error = %v", err)
	}
	if posts.Load() != 0 {
		t.Fatal("update must not be sent when hold is refused locally")
	}
}

func TestContainerUpdateSendsDowntimeConfirmationForReplaceStrategy(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
			_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"running","gpus":8,"update_strategy":"replace"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/containers/"+testContainerID+"/update":
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
			_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"stopping"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	updateYes = true

	if _, err := captureTestStdout(func() error {
		return containerUpdateCmd.RunE(containerUpdateCmd, []string{testContainerID})
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"confirm_downtime":true`) {
		t.Fatalf("body %s lacks confirm_downtime", body)
	}
}

func TestResolveContainerListsBothMatchesWhenNameIsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[
			{"id":"11111111-1111-1111-1111-111111111111","name":"app","debug":false,"domain":"app.containers.tinfoil.dev"},
			{"id":"22222222-2222-2222-2222-222222222222","name":"app","debug":true,"domain":"app-debug.containers.tinfoil.dev"}
		]`)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)

	client, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveContainer(client, "app")
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	for _, want := range []string{"use the ID", "11111111-1111-1111-1111-111111111111  production", "22222222-2222-2222-2222-222222222222  debug"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err.Error(), want)
		}
	}
}
