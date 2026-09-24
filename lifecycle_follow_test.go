package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFollowDeploymentGeneration(t *testing.T) {
	const pendingCandidate = `"status":"running","current_tag":"same-tag","tinfoild_deployment_id":"old","update_tag":"same-tag","update_deployment_id":"new","update_status":"pending","update_type":"blue_green"`
	const readyCandidate = `"status":"running","current_tag":"same-tag","tinfoild_deployment_id":"old","update_tag":"same-tag","update_deployment_id":"new","update_status":"ready","update_type":"blue_green"`
	const promoted = `"status":"running","current_tag":"same-tag","tinfoild_deployment_id":"new","update_deployment_id":null,"update_tag":null`
	const canceled = `"status":"running","current_tag":"same-tag","tinfoild_deployment_id":"old","update_deployment_id":null,"update_tag":null`
	const queued = `"status":"stopping","current_tag":"same-tag","tinfoild_deployment_id":"old","update_tag":"same-tag","update_deployment_id":"new","update_status":"pending","update_type":"queued_deploy"`
	const deploying = `"status":"deploying","current_tag":"same-tag","tinfoild_deployment_id":"new"`
	const stopped = `"status":"stopped","tinfoild_deployment_id":"new"`
	const failed = `"status":"failed","tinfoild_deployment_id":"new","error_message":"workload failed"`
	const boot = `[{"name":"start workload","status":"running"}]`
	for _, tt := range []struct {
		name, initial         string
		polls                 []string
		wantErr, wantProgress string
	}{
		{"hold true overrides false row", pendingCandidate + `,"held":false,"update_config":{"hold":true}`, []string{readyCandidate + `,"held":false,"update_config":{"hold":true}`}, "", "held for review"},
		{"false override follows through promotion", pendingCandidate + `,"held":true,"update_config":{"hold":false}`, []string{readyCandidate + `,"held":true,"update_config":{"hold":false}`, promoted}, "", "switching traffic"},
		{"same-tag cancel is not promote", pendingCandidate, []string{canceled}, "canceled or superseded", ""},
		{"same-tag promote succeeds", pendingCandidate, []string{promoted}, "", "Running"},
		{"candidate replaced", pendingCandidate, []string{strings.ReplaceAll(pendingCandidate, `"new"`, `"other"`)}, "canceled or superseded", ""},
		{"different deployment already running", pendingCandidate, []string{strings.ReplaceAll(promoted, `"new"`, `"other"`)}, "canceled or superseded", ""},
		{"candidate failed", pendingCandidate, []string{strings.ReplaceAll(pendingCandidate, `"pending"`, `"failed"`) + `,"error_message":"candidate failed"`}, "candidate failed", ""},
		{"queued waits while old still running", strings.ReplaceAll(queued, `"stopping"`, `"running"`), []string{queued, strings.ReplaceAll(queued, `"stopping"`, `"stopped"`), deploying, promoted}, "", "Running"},
		{"queued canceled before stop", strings.ReplaceAll(queued, `"stopping"`, `"running"`), []string{canceled}, "canceled or superseded", ""},
		{"queued canceled after stop", queued, []string{`"status":"stopped","tinfoild_deployment_id":null`}, "canceled or superseded", ""},
		{"queued inherited hold cannot finish early", queued, []string{strings.ReplaceAll(queued, `"pending"`, `"ready"`) + `,"held":true`, deploying, promoted}, "", "Running"},
		{"replace follows its generation", strings.ReplaceAll(queued, "queued_deploy", "replace"), []string{deploying, promoted}, "", "Running"},
		{"deploy follows boot stages", deploying, []string{deploying + `,"boot_stages":` + boot, promoted}, "", "start workload"},
		{"deploy decodes backend boot stages", deploying, []string{deploying + `,"boot_stages":"` + base64.StdEncoding.EncodeToString([]byte(boot)) + `"`, promoted}, "", "start workload"},
		{"candidate decodes backend boot stages", pendingCandidate, []string{pendingCandidate + `,"update_boot_stages":"` + base64.StdEncoding.EncodeToString([]byte(boot)) + `"`, promoted}, "", "start workload"},
		{"deploy stopped intentionally", deploying, []string{stopped}, "stopped before completion", ""},
		{"deploy stopping intentionally", deploying, []string{strings.ReplaceAll(stopped, "stopped", "stopping")}, "stopped before completion", ""},
		{"deploy superseded", deploying, []string{strings.ReplaceAll(promoted, `"new"`, `"other"`)}, "canceled or superseded", ""},
		{"deploy failed", deploying, []string{failed}, "workload failed", ""},
		{"missing generation refuses to guess", `"status":"deploying"`, nil, "no deployment ID", ""},
	} {
		for _, render := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/render=%t", tt.name, render), func(t *testing.T) {
				previousInterval, previousOutput, previousNoWait := followInterval, outputFormat, noWait
				followInterval, outputFormat, noWait = 0, "table", false
				t.Cleanup(func() { followInterval, outputFormat, noWait = previousInterval, previousOutput, previousNoWait })
				fixture := func(fields string) string { return `{"id":"` + testContainerID + `","name":"app",` + fields + `}` }
				polls := 0
				client := &cpClient{baseURL: "https://controlplane.example", http: &http.Client{Transport: lifecycleTransport(func(r *http.Request) (*http.Response, error) {
					if r.Method != http.MethodGet || r.URL.Path != "/api/containers/"+testContainerID {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if polls >= len(tt.polls) {
						return nil, fmt.Errorf("unexpected extra poll %d", polls+1)
					}
					body := fixture(tt.polls[polls])
					polls++
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
				})}}
				var initial containerView
				if err := json.Unmarshal([]byte(fixture(tt.initial)), &initial); err != nil {
					t.Fatal(err)
				}
				progress, err := captureTestStderr(func() error {
					if render {
						_, err := captureTestStdout(func() error { return followAndRender(client, initial, nil) })
						return err
					}
					_, err := followContainer(client, initial.ID, initial)
					return err
				})
				if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if polls != len(tt.polls) {
					t.Fatalf("polls = %d, want %d", polls, len(tt.polls))
				}
				if tt.wantProgress != "" && !strings.Contains(string(progress), tt.wantProgress) {
					t.Fatalf("progress lacks %q: %s", tt.wantProgress, progress)
				}
				if tt.wantErr != "" && strings.Contains(string(progress), "Running") {
					t.Fatalf("reported success for interrupted deployment: %s", progress)
				}
			})
		}
	}
}
