package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeleteModelwrapUsesResolvedHostAndJob(t *testing.T) {
	request := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request++
		switch request {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api/models/wrap" || r.URL.Query().Get("limit") != "200" {
				t.Errorf("list request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `[{"id":"job-1","job_id":"job-1","host":"gpu-a","repo":"org/model","commit":"abcdef1","status":"complete"}]`)
		case 2:
			if r.Method != http.MethodDelete || r.URL.Path != "/api/models/wrap/gpu-a/job-1" {
				t.Errorf("delete request = %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %d: %s %s", request, r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := &cpClient{baseURL: server.URL, apiKey: "admin_test", http: server.Client()}
	deleted, err := deleteModelwrap(client, "org/model@abcdef1", "")
	if err != nil {
		t.Fatalf("deleteModelwrap: %v", err)
	}
	if deleted.ID != "job-1" || deleted.Host != "gpu-a" {
		t.Fatalf("deleted = %#v", deleted)
	}
	if request != 2 {
		t.Fatalf("requests = %d, want 2", request)
	}
}

func TestResolveModelwrapRequiresDisambiguation(t *testing.T) {
	models := []modelwrapView{
		{ID: "job-1", Host: "gpu-a", Repo: "org/model", Commit: "abcdef1"},
		{ID: "job-2", Host: "gpu-b", Repo: "org/model", Commit: "abcdef1"},
	}
	if _, err := resolveModelwrapFromList(models, "org/model@abcdef1", ""); err == nil {
		t.Fatal("expected ambiguous model target to fail")
	}
	got, err := resolveModelwrapFromList(models, "org/model@abcdef1", "gpu-b")
	if err != nil {
		t.Fatalf("resolve with host: %v", err)
	}
	if got.ID != "job-2" {
		t.Fatalf("resolved job = %s, want job-2", got.ID)
	}
}
