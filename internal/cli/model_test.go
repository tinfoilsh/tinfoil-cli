package cli

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

func configureModelCommandTest(commandState *commandFixture, t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))

	previousOutput := commandState.outputOpts.outputFormat
	previousHost := commandState.modelWrapOpts.modelWrapHost
	previousCommit := commandState.modelWrapOpts.modelWrapCommit
	previousToken := commandState.modelWrapOpts.modelWrapHFToken
	previousTokenFile := commandState.modelWrapOpts.modelWrapHFTokenFile
	previousWait := commandState.modelWrapOpts.modelWrapWait
	previousLimit := commandState.modelListOpts.modelListLimit
	previousStatusWait := commandState.modelStatusOpts.modelStatusWait
	previousStatusLogs := commandState.modelStatusOpts.modelStatusLogs
	previousUpdateHost := commandState.modelUpdateOpts.modelUpdateHost
	previousUpdateCommit := commandState.modelUpdateOpts.modelUpdateCommit
	previousUpdateToken := commandState.modelUpdateOpts.modelUpdateHFToken
	previousUpdateTokenFile := commandState.modelUpdateOpts.modelUpdateHFTokenFile
	previousUpdateWait := commandState.modelUpdateOpts.modelUpdateWait
	previousInterval := commandState.pollingOpts.modelWrapPollInterval
	tokenFlag := commandState.modelWrapCmd.Flags().Lookup("hf-token")
	tokenFileFlag := commandState.modelWrapCmd.Flags().Lookup("hf-token-file")
	updateTokenFlag := commandState.modelUpdateCmd.Flags().Lookup("hf-token")
	updateTokenFileFlag := commandState.modelUpdateCmd.Flags().Lookup("hf-token-file")
	previousTokenChanged := tokenFlag.Changed
	previousTokenFileChanged := tokenFileFlag.Changed
	previousUpdateTokenChanged := updateTokenFlag.Changed
	previousUpdateTokenFileChanged := updateTokenFileFlag.Changed

	t.Cleanup(func() {
		commandState.outputOpts.outputFormat = previousOutput
		commandState.modelWrapOpts.modelWrapHost = previousHost
		commandState.modelWrapOpts.modelWrapCommit = previousCommit
		commandState.modelWrapOpts.modelWrapHFToken = previousToken
		commandState.modelWrapOpts.modelWrapHFTokenFile = previousTokenFile
		commandState.modelWrapOpts.modelWrapWait = previousWait
		commandState.modelListOpts.modelListLimit = previousLimit
		commandState.modelStatusOpts.modelStatusWait = previousStatusWait
		commandState.modelStatusOpts.modelStatusLogs = previousStatusLogs
		commandState.modelUpdateOpts.modelUpdateHost = previousUpdateHost
		commandState.modelUpdateOpts.modelUpdateCommit = previousUpdateCommit
		commandState.modelUpdateOpts.modelUpdateHFToken = previousUpdateToken
		commandState.modelUpdateOpts.modelUpdateHFTokenFile = previousUpdateTokenFile
		commandState.modelUpdateOpts.modelUpdateWait = previousUpdateWait
		commandState.pollingOpts.modelWrapPollInterval = previousInterval
		tokenFlag.Changed = previousTokenChanged
		tokenFileFlag.Changed = previousTokenFileChanged
		updateTokenFlag.Changed = previousUpdateTokenChanged
		updateTokenFileFlag.Changed = previousUpdateTokenFileChanged
	})

	commandState.outputOpts.outputFormat = "table"
	commandState.modelWrapOpts.modelWrapHost = ""
	commandState.modelWrapOpts.modelWrapCommit = ""
	commandState.modelWrapOpts.modelWrapHFToken = ""
	commandState.modelWrapOpts.modelWrapHFTokenFile = ""
	commandState.modelWrapOpts.modelWrapWait = false
	commandState.modelListOpts.modelListLimit = 0
	commandState.modelStatusOpts.modelStatusWait = false
	commandState.modelStatusOpts.modelStatusLogs = false
	commandState.modelUpdateOpts.modelUpdateHost = ""
	commandState.modelUpdateOpts.modelUpdateCommit = ""
	commandState.modelUpdateOpts.modelUpdateHFToken = ""
	commandState.modelUpdateOpts.modelUpdateHFTokenFile = ""
	commandState.modelUpdateOpts.modelUpdateWait = false
	tokenFlag.Changed = false
	tokenFileFlag.Changed = false
	updateTokenFlag.Changed = false
	updateTokenFileFlag.Changed = false
}

func TestModelWrapSendsRequestBody(t *testing.T) {
	commandState := newCommandFixture()

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

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelWrapOpts.modelWrapHost = "gpu-1"
	commandState.modelWrapOpts.modelWrapCommit = "419b2efe421994fdfd3394e621983d4cc511cd4f"

	output, err := captureTestStdout(func() error {
		return commandState.modelWrapCmd.RunE(commandState.modelWrapCmd, []string{"acme/model"})
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
	commandState := newCommandFixture()

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

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelWrapOpts.modelWrapHost = "gpu-1"

	if _, err := captureTestStdout(func() error {
		return commandState.modelWrapCmd.RunE(commandState.modelWrapCmd, []string{"acme/model"})
	}); err != nil {
		t.Fatalf("run model wrap: %v", err)
	}
}

func TestModelWrapWaitPollsUntilComplete(t *testing.T) {
	commandState := newCommandFixture()

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

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelWrapOpts.modelWrapHost = "gpu-1"
	commandState.modelWrapOpts.modelWrapWait = true
	commandState.pollingOpts.modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return commandState.modelWrapCmd.RunE(commandState.modelWrapCmd, []string{"acme/model"})
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
	commandState := newCommandFixture()

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

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelWrapOpts.modelWrapHost = "gpu-1"
	commandState.modelWrapOpts.modelWrapWait = true
	commandState.pollingOpts.modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return commandState.modelWrapCmd.RunE(commandState.modelWrapCmd, []string{"acme/model"})
	})
	if err == nil {
		t.Fatal("model wrap --wait succeeded for a failed job")
	}
	if !strings.Contains(string(output), "Error:    download failed") {
		t.Fatalf("output does not include the job error:\n%s", output)
	}
}

func TestModelListPassesLimit(t *testing.T) {
	commandState := newCommandFixture()

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

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelListOpts.modelListLimit = 5

	output, err := captureTestStdout(func() error {
		return commandState.modelListCmd.RunE(commandState.modelListCmd, nil)
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
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"acme/model","status":"failed","error":"download failed"}`)
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelStatusOpts.modelStatusWait = true
	commandState.pollingOpts.modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return commandState.modelStatusCmd.RunE(commandState.modelStatusCmd, []string{"gpu-1", "job-1"})
	})
	if err == nil {
		t.Fatal("model status --wait succeeded for a failed job")
	}
	if !strings.Contains(string(output), "Error:    download failed") {
		t.Fatalf("output does not include the job error:\n%s", output)
	}
}

func TestModelStatusRendersConfigBlock(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("request = %s %s, want GET /api/models/wrap/gpu-1/job-1", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"job_id":"job-1","host":"gpu-1","repo":"google/gemma-4-31B-it","commit":"419b2efe421994fdfd3394e621983d4cc511cd4f","status":"complete","root_hash":"0900ca6b","offset":62578683904,"verity_uuid":"59fe9787-ed93-577a-9fd9-a7804c932a11"}`)
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)

	output, err := captureTestStdout(func() error {
		return commandState.modelStatusCmd.RunE(commandState.modelStatusCmd, []string{"gpu-1", "job-1"})
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
	commandState := newCommandFixture()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/models/wrap/gpu-1/job-1" {
			t.Fatalf("request = %s %s, want DELETE /api/models/wrap/gpu-1/job-1", r.Method, r.URL.Path)
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)

	output, err := captureTestStdout(func() error {
		return commandState.modelDeleteCmd.RunE(commandState.modelDeleteCmd, []string{"gpu-1", "job-1"})
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
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"model artifact is referenced by a running deployment"}`)
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)

	_, err := captureTestStdout(func() error {
		return commandState.modelDeleteCmd.RunE(commandState.modelDeleteCmd, []string{"gpu-1", "job-1"})
	})
	if err == nil {
		t.Fatal("model delete succeeded on a 409 response")
	}
	if !strings.Contains(err.Error(), "referenced by a running deployment") {
		t.Fatalf("error does not surface the conflict message: %v", err)
	}
}

const modelUpdateOldJob = `{"job_id":"old-job","host":"gpu-1","repo":"acme/model","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"complete","root_hash":"11aa","offset":100,"verity_uuid":"59fe9787-ed93-577a-9fd9-a7804c932a11"}`

func TestModelUpdateResolvesLatestCommitAndWraps(t *testing.T) {
	commandState := newCommandFixture()

	var wrapBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap":
			_, _ = io.WriteString(w, `[`+modelUpdateOldJob+`]`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/huggingface/models/acme/model":
			if got := r.Header.Get("X-HuggingFace-Token"); got != "hf_secret" {
				t.Fatalf("X-HuggingFace-Token = %q, want hf_secret", got)
			}
			_, _ = io.WriteString(w, `{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/wrap":
			if err := json.NewDecoder(r.Body).Decode(&wrapBody); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"job_id":"new-job","host":"gpu-1","repo":"acme/model","status":"pending"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelUpdateOpts.modelUpdateHost = "gpu-1"
	commandState.modelUpdateOpts.modelUpdateHFToken = "hf_secret"
	commandState.modelUpdateCmd.Flags().Lookup("hf-token").Changed = true

	output, err := captureTestStdout(func() error {
		return commandState.modelUpdateCmd.RunE(commandState.modelUpdateCmd, []string{"acme/model"})
	})
	if err != nil {
		t.Fatalf("run model update: %v", err)
	}
	if got := wrapBody["commit"]; got != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("wrap commit = %v, want the HF latest sha", got)
	}
	if got := wrapBody["hf_token"]; got != "hf_secret" {
		t.Fatalf("wrap hf_token = %v, want hf_secret", got)
	}
	for _, want := range []string{
		"Updating acme/model on gpu-1: aaaaaaaaaaaa -> bbbbbbbbbbbb",
		"tinfoil model status gpu-1 new-job",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestModelUpdateAlreadyUpToDate(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap":
			_, _ = io.WriteString(w, `[`+modelUpdateOldJob+`]`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/huggingface/models/acme/model":
			_, _ = io.WriteString(w, `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelUpdateOpts.modelUpdateHost = "gpu-1"

	output, err := captureTestStdout(func() error {
		return commandState.modelUpdateCmd.RunE(commandState.modelUpdateCmd, []string{"acme/model"})
	})
	if err != nil {
		t.Fatalf("run model update: %v", err)
	}
	if !strings.Contains(string(output), "already at commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (job old-job)") {
		t.Fatalf("output does not report up-to-date:\n%s", output)
	}
}

func TestModelUpdateRequiresPriorWrap(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"job_id":"other","host":"gpu-2","repo":"acme/model","status":"complete"},{"job_id":"failed","host":"gpu-1","repo":"acme/model","status":"failed"}]`)
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelUpdateOpts.modelUpdateHost = "gpu-1"

	_, err := captureTestStdout(func() error {
		return commandState.modelUpdateCmd.RunE(commandState.modelUpdateCmd, []string{"acme/model"})
	})
	if err == nil || !strings.Contains(err.Error(), "tinfoil model wrap") {
		t.Fatalf("error = %v, want a hint to run tinfoil model wrap", err)
	}
}

func TestModelUpdateWaitPrintsReclaimHint(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap":
			_, _ = io.WriteString(w, `[`+modelUpdateOldJob+`]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/models/wrap":
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"job_id":"new-job","host":"gpu-1","repo":"acme/model","status":"pending"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/wrap/gpu-1/new-job":
			_, _ = io.WriteString(w, `{"job_id":"new-job","host":"gpu-1","repo":"acme/model","commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"complete","root_hash":"22bb","offset":200,"verity_uuid":"59fe9787-ed93-577a-9fd9-a7804c932a11"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	configureModelCommandTest(commandState, t, server.URL)
	commandState.modelUpdateOpts.modelUpdateHost = "gpu-1"
	commandState.modelUpdateOpts.modelUpdateCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	commandState.modelUpdateOpts.modelUpdateWait = true
	commandState.pollingOpts.modelWrapPollInterval = time.Millisecond

	output, err := captureTestStdout(func() error {
		return commandState.modelUpdateCmd.RunE(commandState.modelUpdateCmd, []string{"acme/model"})
	})
	if err != nil {
		t.Fatalf("run model update --wait: %v", err)
	}
	for _, want := range []string{
		`mpk: "22bb_200_59fe9787-ed93-577a-9fd9-a7804c932a11"`,
		"tinfoil model delete gpu-1 old-job",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestLatestCompleteModelWrapPicksNewestRegardlessOfOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "200" {
			t.Fatalf("limit = %q, want 200", got)
		}
		// Oldest first, i.e. the opposite of the server's usual ordering.
		_, _ = io.WriteString(w, `[
			{"job_id":"older","host":"gpu-1","repo":"acme/model","status":"complete","started_at":"2026-08-01T00:00:00Z"},
			{"job_id":"running","host":"gpu-1","repo":"acme/model","status":"running","started_at":"2026-08-31T00:00:00Z"},
			{"job_id":"newer","host":"gpu-1","repo":"acme/model","status":"complete","started_at":"2026-08-20T00:00:00Z"},
			{"job_id":"other-host","host":"gpu-2","repo":"acme/model","status":"complete","started_at":"2026-08-30T00:00:00Z"}
		]`)
	}))
	defer server.Close()

	client := &cpClient{baseURL: server.URL, http: server.Client()}
	job, err := latestCompleteModelWrap(client, "acme/model", "gpu-1")
	if err != nil {
		t.Fatalf("latestCompleteModelWrap: %v", err)
	}
	if job == nil || job.JobID != "newer" {
		t.Fatalf("job = %+v, want the newer completed job", job)
	}

	job, err = latestCompleteModelWrap(client, "acme/other", "gpu-1")
	if err != nil {
		t.Fatalf("latestCompleteModelWrap: %v", err)
	}
	if job != nil {
		t.Fatalf("job = %+v, want nil for an unwrapped repo", job)
	}
}

func TestReadHFTokenFlagsMutuallyExclusive(t *testing.T) {
	commandState := newCommandFixture()

	configureModelCommandTest(commandState, t, "https://example.invalid")
	commandState.modelWrapCmd.Flags().Lookup("hf-token").Changed = true
	commandState.modelWrapCmd.Flags().Lookup("hf-token-file").Changed = true

	if _, err := readHFToken(commandState.modelWrapCmd); err == nil {
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
