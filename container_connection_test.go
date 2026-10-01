package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

const reviewContainerFixture = `{"id":"61bd4a3e-5b48-4320-9215-0c7a7f974979","name":"app","repo":"acme/app","status":"running","current_tag":"v1","domain":"production.example.com","update_tag":"v2","update_status":"ready","update_type":"blue_green","update_deployment_id":"candidate-1","update_config":{"hold":true},"connections":{"production":{"url":"https://production.example.com","repo":"acme/app","tag":"v1"},"review":{"url":"https://review.example.com:4443","repo":"acme/app","tag":"v2"}}}`

func reviewContainer(t *testing.T) containerView {
	t.Helper()
	var c containerView
	if err := json.Unmarshal([]byte(reviewContainerFixture), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFollowReadyPrintsVerifiedCandidateRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, reviewContainerFixture) }))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	oldInterval := followInterval
	followInterval = time.Millisecond
	t.Cleanup(func() { followInterval = oldInterval })
	outputFormat, noWait = "table", false
	c := reviewContainer(t)
	c.UpdateStatus = statusDeploying
	c.Connections.Review = nil
	out, err := captureTestStdout(func() error { return followAndRender(newCPClient(cliConfig{ControlplaneURL: server.URL}), c, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "tinfoil http get https://review.example.com:4443 --enclave review.example.com:4443 --repo acme/app@v2") {
		t.Fatalf("missing ready request: %s", out)
	}
}

func TestReviewConnectInvalidHostFailsBeforeProxy(t *testing.T) {
	c := reviewContainer(t)
	c.Connections.Review.URL = "https://bad host:4443"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(c) }))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	oldRun, oldRepo := proxyCmd.RunE, repo
	t.Cleanup(func() { proxyCmd.RunE = oldRun; repo = oldRepo })
	repo = ""
	proxyCmd.RunE = func(_ *cobra.Command, _ []string) error { t.Fatal("proxy started for invalid host"); return nil }
	_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "container", "connect", testContainerID, "--review") })
	if err == nil || !strings.Contains(err.Error(), "invalid review connection") || !strings.Contains(err.Error(), "invalid HTTPS URL/host") {
		t.Fatalf("error %v", err)
	}
}

func TestCreateRunningPrintsVerifiedNextStep(t *testing.T) {
	c := reviewContainer(t)
	c.UpdateTag, c.UpdateStatus, c.UpdateType, c.UpdateDeploymentID = "", "", "", ""
	c.TinfoildDeploymentID = "deployment-1"
	c.Connections.Review = nil
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/containers/validate":
			io.WriteString(w, `{"valid":true,"config":{"volumes":[]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/containers":
			io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"deploying","tinfoild_deployment_id":"deployment-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
			json.NewEncoder(w).Encode(c)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	noWait = false
	oldInterval := followInterval
	followInterval = time.Millisecond
	t.Cleanup(func() { followInterval = oldInterval })
	out, err := captureTestStdout(func() error {
		return executeLifecycleCLI(t, "container", "create", "app", "--repo", "acme/app", "--tag", "v1", "-o", "table")
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Production URL: https://production.example.com", "--enclave production.example.com --repo acme/app@v1", "tinfoil container connect " + testContainerID} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing first request guidance %q: %s", want, out)
		}
	}
}

func TestReviewConnectionPinsCandidate(t *testing.T) {
	c := reviewContainer(t)
	for _, review := range []bool{false, true} {
		target, err := containerConnection(c, review, "")
		if err != nil {
			t.Fatal(err)
		}
		wantHost, wantSource := "production.example.com", "acme/app@v1"
		if review {
			wantHost, wantSource = "review.example.com:4443", "acme/app@v2"
		}
		if target.host != wantHost || target.source != wantSource {
			t.Fatalf("wrong target: %+v", target)
		}
		secure, err := newVerifiedClient(target.host, target.source, "")
		if err != nil || secure.Repo() != wantSource || secure.Enclave() != wantHost {
			t.Fatalf("lost SDK verification pins: %v", err)
		}
	}
	for _, source := range []string{"acme/app", "acme/app@v1", "other/app@v2", "bad reference"} {
		if _, err := containerConnection(c, true, source); err == nil {
			t.Fatalf("review accepted override %q", source)
		}
	}
	digestPin := "acme/app@v2@sha256:" + strings.Repeat("a", 64)
	if target, err := containerConnection(c, true, digestPin); err != nil || target.source != digestPin {
		t.Fatalf("digest override: %+v %v", target, err)
	}
	if target, err := containerConnection(c, false, "acme/other@release"); err != nil || target.source != "acme/other@release" {
		t.Fatalf("explicit production --repo ignored: %+v %v", target, err)
	}
}

func TestReviewRejectsUnavailableCandidate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*containerView)
	}{
		{"absent descriptors", func(c *containerView) { c.Connections = nil }},
		{"absent review", func(c *containerView) { c.Connections.Review = nil }},
		{"failed", func(c *containerView) { c.UpdateStatus = statusFailed }},
		{"deploying", func(c *containerView) { c.UpdateStatus = statusDeploying }},
		{"pending", func(c *containerView) { c.UpdateStatus = statusPending }},
		{"replace", func(c *containerView) { c.UpdateType = updateStrategyReplace }},
		{"queued", func(c *containerView) { c.UpdateType = updateTypeQueuedDeploy }},
		{"missing deployment", func(c *containerView) { c.UpdateDeploymentID = "" }},
		{"placeholder deployment", func(c *containerView) { c.UpdateDeploymentID = "pending:update" }},
		{"unknown update type", func(c *containerView) { c.UpdateType = "unknown" }},
		{"missing tag", func(c *containerView) { c.UpdateTag = "" }},
		{"wrong tag", func(c *containerView) { c.Connections.Review.Tag = "v1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := reviewContainer(t)
			tc.change(&c)
			if _, err := containerConnection(c, true, ""); err == nil {
				t.Fatal("fell back to production or accepted unavailable review")
			}
		})
	}
}

func TestConnectionRejectsInvalidHostAndSource(t *testing.T) {
	for _, raw := range []string{"http://review.example.com:4443", "https://", "https://user:pass@review.example.com", "https://bad host", "https://review.example.com/path", "https://review.example.com?secret=x", "https://review.example.com#fragment", "https://review.example.com:99999", "https://review.example.com:", "https://bad_host", "https://-bad.example.com"} {
		t.Run(raw, func(t *testing.T) {
			c := reviewContainer(t)
			c.Connections.Review.URL = raw
			if _, err := containerConnection(c, true, ""); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("invalid host accepted: %v", err)
			}
		})
	}
	for _, ref := range []connectionDescriptor{{URL: "https://valid.example.com", Repo: "acme/app", Tag: ""}, {URL: "https://valid.example.com", Repo: "acme/app@v1", Tag: "v2"}} {
		if _, err := parseConnectionDescriptor(ref); err == nil {
			t.Fatal("malformed release accepted")
		}
	}
}

func TestReviewConnectCommandUsesActualDescriptor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/containers/"+testContainerID {
			t.Errorf("unexpected lookup %s", r.URL)
		}
		io.WriteString(w, reviewContainerFixture)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	oldRun, oldRepo, oldHost, oldReview := proxyCmd.RunE, repo, enclaveHost, connectReview
	t.Cleanup(func() { proxyCmd.RunE = oldRun; repo = oldRepo; enclaveHost = oldHost; connectReview = oldReview })
	repo = ""
	called := false
	proxyCmd.RunE = func(_ *cobra.Command, _ []string) error {
		called = true
		if enclaveHost != "review.example.com:4443" || repo != "acme/app@v2" {
			t.Fatalf("proxy target %s %s", enclaveHost, repo)
		}
		return nil
	}
	_, err := captureTestStdout(func() error { return executeLifecycleCLI(t, "container", "connect", testContainerID, "--review") })
	if err != nil || !called {
		t.Fatalf("connect err=%v called=%t", err, called)
	}
}

func TestContainerGetAndReadyOutputShowVerifiedNextSteps(t *testing.T) {
	old := outputFormat
	outputFormat = "table"
	t.Cleanup(func() { outputFormat = old })
	for _, held := range []bool{false, true} {
		c := reviewContainer(t)
		if !held {
			c.UpdateTag = ""
			c.UpdateDeploymentID = ""
			c.Connections.Review = nil
		}
		out, err := captureTestStdout(func() error { return renderContainer(c) })
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Production URL: https://production.example.com", "Expected source: acme/app@v1", "tinfoil http get https://production.example.com --enclave production.example.com --repo acme/app@v1", "tinfoil container connect " + testContainerID} {
			if !strings.Contains(string(out), want) {
				t.Fatalf("missing %q: %s", want, out)
			}
		}
		if held && (!strings.Contains(string(out), "Review URL: https://review.example.com:4443") || !strings.Contains(string(out), "--enclave review.example.com:4443 --repo acme/app@v2") || !strings.Contains(string(out), "--review")) {
			t.Fatalf("missing review guidance: %s", out)
		}
	}
}

func TestFollowConnectionGuidancePreservesChangesWithoutDuplicates(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		change                 func(*containerView, *containerView)
		production, review     int
		want                   []string
		wantErr                string
		noWait, json, terminal bool
	}{
		{name: "identical endpoints and pins", production: 1, review: 1},
		{name: "production endpoint changes", production: 2, review: 1, change: func(_, final *containerView) {
			final.Connections.Production.URL = "https://new-production.example.com"
		}, want: []string{"Production URL: https://production.example.com", "Production URL: https://new-production.example.com"}},
		{name: "production repository changes", production: 2, review: 1, change: func(_, final *containerView) {
			final.Connections.Production.Repo = "acme/other"
		}, want: []string{"--repo acme/app@v1", "--repo acme/other@v1"}},
		{name: "promotion changes pin at same URL", production: 2, review: 1, change: func(_, final *containerView) {
			final.CurrentTag, final.Connections.Production.Tag = "v2", "v2"
			final.TinfoildDeploymentID = final.UpdateDeploymentID
			final.UpdateDeploymentID, final.UpdateTag, final.UpdateType, final.UpdateStatus = "", "", "", ""
			final.Connections.Review = nil
		}, want: []string{
			"tinfoil http get https://production.example.com --enclave production.example.com --repo acme/app@v1",
			"tinfoil http get https://production.example.com --enclave production.example.com --repo acme/app@v2",
		}},
		{name: "same-tag replacement", production: 1, review: 0, change: func(initial, final *containerView) {
			initial.UpdateType, initial.UpdateTag = updateStrategyReplace, "v1"
			initial.Connections.Review, final.Connections.Review = nil, nil
			final.TinfoildDeploymentID = initial.UpdateDeploymentID
			final.UpdateDeploymentID, final.UpdateTag, final.UpdateType, final.UpdateStatus = "", "", "", ""
		}},
		{name: "review becomes available", production: 1, review: 1, change: func(initial, _ *containerView) {
			initial.UpdateStatus, initial.Connections.Review = statusDeploying, nil
		}, want: []string{"Review URL: https://review.example.com:4443", "--repo acme/app@v2"}},
		{name: "unchanged descriptor becomes usable", production: 1, review: 1, change: func(initial, _ *containerView) {
			initial.UpdateStatus = statusDeploying
		}, want: []string{"Review unavailable:", "Review URL: https://review.example.com:4443"}},
		{name: "review endpoint changes", production: 1, review: 2, change: func(_, final *containerView) {
			final.Connections.Review.URL = "https://new-review.example.com:4443"
		}, want: []string{"Review URL: https://review.example.com:4443", "Review URL: https://new-review.example.com:4443"}},
		{name: "review pin changes", production: 1, review: 2, change: func(_, final *containerView) {
			final.UpdateTag, final.Connections.Review.Tag = "v3", "v3"
		}, want: []string{"--repo acme/app@v2", "--repo acme/app@v3"}},
		{name: "review repository changes", production: 1, review: 2, change: func(_, final *containerView) {
			final.Connections.Review.Repo = "acme/other"
		}, want: []string{"--repo acme/app@v2", "--repo acme/other@v2"}},
		{name: "no-wait keeps initial guidance", production: 1, review: 1, noWait: true},
		{name: "already terminal keeps initial guidance", production: 1, review: 1, terminal: true},
		{name: "JSON remains initial response", json: true},
		{name: "failed follow keeps initial guidance", production: 1, review: 1, change: func(_, final *containerView) {
			final.UpdateStatus, final.ErrorMessage = statusFailed, "workload failed"
		}, wantErr: "workload failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousInterval, previousOutput, previousNoWait := followInterval, outputFormat, noWait
			followInterval, outputFormat, noWait = 0, "table", tc.noWait
			if tc.json {
				outputFormat = "json"
			}
			t.Cleanup(func() { followInterval, outputFormat, noWait = previousInterval, previousOutput, previousNoWait })
			initial, final := reviewContainer(t), reviewContainer(t)
			if !tc.terminal {
				initial.UpdateStatus = statusStarted
			}
			if tc.change != nil {
				tc.change(&initial, &final)
			}
			body, err := json.Marshal(final)
			if err != nil {
				t.Fatal(err)
			}
			polls := 0
			client := &cpClient{baseURL: "https://controlplane.example", http: &http.Client{Transport: lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				polls++
				if polls > 1 || r.Method != http.MethodGet || r.URL.Path != "/api/containers/"+testContainerID {
					return nil, fmt.Errorf("unexpected follow request: %s %s (poll %d)", r.Method, r.URL.Path, polls)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
			})}}
			var stdout []byte
			_, err = captureTestStderr(func() error {
				var runErr error
				stdout, runErr = captureTestStdout(func() error { return followAndRender(client, initial, nil) })
				return runErr
			})
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("follow error=%v, want %q", err, tc.wantErr)
			}
			wantPolls := 1
			if tc.noWait || tc.json || tc.terminal {
				wantPolls = 0
			}
			if polls != wantPolls {
				t.Fatalf("polls=%d, want %d", polls, wantPolls)
			}
			out := string(stdout)
			if strings.Count(out, "Production URL:") != tc.production || strings.Count(out, "Review URL:") != tc.review {
				t.Fatalf("incorrect connection block counts, want production=%d review=%d:\n%s", tc.production, tc.review, out)
			}
			last := -1
			for _, want := range tc.want {
				index := strings.Index(out, want)
				if index < 0 || index <= last {
					t.Fatalf("missing or out-of-order guidance %q:\n%s", want, out)
				}
				last = index
			}
			if tc.json {
				var decoded containerView
				if err := json.Unmarshal(stdout, &decoded); err != nil || decoded.UpdateStatus != initial.UpdateStatus {
					t.Fatalf("initial JSON changed: %s (%v)", stdout, err)
				}
			}
		})
	}
}
