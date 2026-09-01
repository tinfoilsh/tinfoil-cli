package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func configureModelCommandTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAPIKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))

	previousOutput := outputFormat
	previousHost := modelWrapHost
	previousCommit := modelWrapCommit
	previousToken := modelWrapHFToken
	previousTokenFile := modelWrapHFTokenFile
	previousWait := modelWrapWait
	previousLimit := modelListLimit
	previousStatusWait := modelStatusWait
	previousStatusLogs := modelStatusLogs
	previousInterval := modelWrapPollInterval
	tokenFlag := modelWrapCmd.Flags().Lookup("hf-token")
	tokenFileFlag := modelWrapCmd.Flags().Lookup("hf-token-file")
	previousTokenChanged := tokenFlag.Changed
	previousTokenFileChanged := tokenFileFlag.Changed

	t.Cleanup(func() {
		outputFormat = previousOutput
		modelWrapHost = previousHost
		modelWrapCommit = previousCommit
		modelWrapHFToken = previousToken
		modelWrapHFTokenFile = previousTokenFile
		modelWrapWait = previousWait
		modelListLimit = previousLimit
		modelStatusWait = previousStatusWait
		modelStatusLogs = previousStatusLogs
		modelWrapPollInterval = previousInterval
		tokenFlag.Changed = previousTokenChanged
		tokenFileFlag.Changed = previousTokenFileChanged
	})

	outputFormat = "table"
	modelWrapHost = ""
	modelWrapCommit = ""
	modelWrapHFToken = ""
	modelWrapHFTokenFile = ""
	modelWrapWait = false
	modelListLimit = 0
	modelStatusWait = false
	modelStatusLogs = false
	tokenFlag.Changed = false
	tokenFileFlag.Changed = false
}

func TestModelWrapSendsRequestBody(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/models/wrap" {
			t.Fatalf("request = %s %s, want POST /api/models/wrap", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"pending"}`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelWrapHost = "gpu-1"
	modelWrapCommit = "419b2efe421994fdfd3394e621983d4cc511cd4f"

	output, err := captureTestStdout(func() error {
		return modelWrapCmd.RunE(modelWrapCmd, []string{"acme/model"})
	})
	if err != nil {
		t.Fatalf("run model wrap: %v", err)
	}

	want := map[string]any{
		"repo":   "acme/model",
		"host":   "gpu-1",
		"commit": "419b2efe421994fdfd3394e621983d4cc511cd4f",
	}
	if len(gotBody) != len(want) {
		t.Fatalf("request body = %v, want %v", gotBody, want)
	}
	for k, v := range want {
		if gotBody[k] != v {
			t.Fatalf("request body %s = %v, want %v", k, gotBody[k], v)
		}
	}
	if !strings.Contains(string(output), "tinfoil model status gpu-1 job-1") {
		t.Fatalf("output does not include the poll hint:\n%s", output)
	}
}

func TestModelWrapOmitsEmptyOptionalFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		for _, key := range []string{"commit", "hf_token"} {
			if _, ok := body[key]; ok {
				t.Fatalf("request body includes %s for unset flag: %v", key, body)
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"pending"}`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelWrapHost = "gpu-1"

	if _, err := captureTestStdout(func() error {
		return modelWrapCmd.RunE(modelWrapCmd, []string{"acme/model"})
	}); err != nil {
		t.Fatalf("run model wrap: %v", err)
	}
}

func TestModelWrapWaitPollsUntilComplete(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/wrap":
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"pending"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap/gpu-1/job-1":
			if polls.Add(1) < 3 {
				_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"running"}`)
				return
			}
			_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","commit":"419b2efe421994fdfd3394e621983d4cc511cd4f","status":"complete","root_hash":"0900ca6b","offset":62578683904,"verity_uuid":"59fe9787-ed93-577a-9fd9-a7804c932a11"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelWrapHost = "gpu-1"
	modelWrapWait = true
	modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return modelWrapCmd.RunE(modelWrapCmd, []string{"acme/model"})
	})
	if err != nil {
		t.Fatalf("run model wrap --wait: %v", err)
	}
	if polls.Load() < 3 {
		t.Fatalf("polled %d times, want at least 3", polls.Load())
	}
	for _, want := range []string{
		`repo: "acme/model@419b2efe421994fdfd3394e621983d4cc511cd4f"`,
		`mpk: "0900ca6b_62578683904_59fe9787-ed93-577a-9fd9-a7804c932a11"`,
		"/tinfoil/mpk/mpk-0900ca6b",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestModelWrapWaitFailsOnFailedJob(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/wrap":
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"pending"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap/gpu-1/job-1":
			_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"failed","error":"download failed"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelWrapHost = "gpu-1"
	modelWrapWait = true
	modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return modelWrapCmd.RunE(modelWrapCmd, []string{"acme/model"})
	})
	if err == nil {
		t.Fatal("model wrap --wait succeeded for a failed job")
	}
	if !strings.Contains(string(output), "Error:    download failed") {
		t.Fatalf("output does not include the job error:\n%s", output)
	}
}

func TestModelListPassesLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap" {
			t.Fatalf("request = %s %s, want GET /api/models/wrap", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("limit = %q, want 5", got)
		}
		_, _ = io.WriteString(w, `[{"job_id":"job-1","host":"gpu-1","repo":"acme/model","commit":"419b2efe","status":"complete","started_at":"2026-08-31T10:00:00Z"}]`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelListLimit = 5

	output, err := captureTestStdout(func() error {
		return modelListCmd.RunE(modelListCmd, nil)
	})
	if err != nil {
		t.Fatalf("run model list: %v", err)
	}
	for _, want := range []string{"JOB ID", "job-1", "gpu-1", "acme/model", "complete"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestModelStatusWaitFailsOnFailedJob(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"failed","error":"download failed"}`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)
	modelStatusWait = true
	modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return modelStatusCmd.RunE(modelStatusCmd, []string{"gpu-1", "job-1"})
	})
	if err == nil {
		t.Fatal("model status --wait succeeded for a failed job")
	}
	if !strings.Contains(string(output), "Error:    download failed") {
		t.Fatalf("output does not include the job error:\n%s", output)
	}
}

func TestModelStatusRendersConfigBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("request = %s %s, want GET /api/models/wrap/gpu-1/job-1", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"google/gemma-4-31B-it","commit":"419b2efe421994fdfd3394e621983d4cc511cd4f","status":"complete","root_hash":"0900ca6b","offset":62578683904,"verity_uuid":"59fe9787-ed93-577a-9fd9-a7804c932a11"}`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)

	output, err := captureTestStdout(func() error {
		return modelStatusCmd.RunE(modelStatusCmd, []string{"gpu-1", "job-1"})
	})
	if err != nil {
		t.Fatalf("run model status: %v", err)
	}
	for _, want := range []string{
		`name: "gemma-4-31b-it"`,
		`repo: "google/gemma-4-31B-it@419b2efe421994fdfd3394e621983d4cc511cd4f"`,
		`mpk: "0900ca6b_62578683904_59fe9787-ed93-577a-9fd9-a7804c932a11"`,
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestModelDeleteSendsRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("request = %s %s, want DELETE /api/models/wrap/gpu-1/job-1", r.Method, r.URL.Path)
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)

	output, err := captureTestStdout(func() error {
		return modelDeleteCmd.RunE(modelDeleteCmd, []string{"gpu-1", "job-1"})
	})
	if err != nil {
		t.Fatalf("run model delete: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("delete requests = %d, want 1", requests.Load())
	}
	if !strings.Contains(string(output), "Deleted model wrap job job-1 on gpu-1") {
		t.Fatalf("output does not confirm deletion:\n%s", output)
	}
}

func TestModelDeleteSurfacesConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"model artifact is referenced by a running deployment"}`)
	}))
	defer server.Close()

	configureModelCommandTest(t, server.URL)

	_, err := captureTestStdout(func() error {
		return modelDeleteCmd.RunE(modelDeleteCmd, []string{"gpu-1", "job-1"})
	})
	if err == nil {
		t.Fatal("model delete succeeded on a 409 response")
	}
	if !strings.Contains(err.Error(), "referenced by a running deployment") {
		t.Fatalf("error does not surface the conflict message: %v", err)
	}
}

func TestReadHFTokenFlagsMutuallyExclusive(t *testing.T) {
	configureModelCommandTest(t, "https://example.invalid")
	modelWrapCmd.Flags().Lookup("hf-token").Changed = true
	modelWrapCmd.Flags().Lookup("hf-token-file").Changed = true

	if _, err := readHFToken(modelWrapCmd); err == nil {
		t.Fatal("readHFToken accepted both --hf-token and --hf-token-file")
	}
}

func TestModelNameFromRepo(t *testing.T) {
	for repo, want := range map[string]string{
		"google/gemma-4-31B-it": "gemma-4-31b-it",
		"acme/Model":            "model",
		"standalone":            "standalone",
	} {
		if got := modelNameFromRepo(repo); got != want {
			t.Fatalf("modelNameFromRepo(%q) = %q, want %q", repo, got, want)
		}
	}
}
