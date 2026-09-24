package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeployAttachRecoveryPreservesRequestedReleaseChoice(t *testing.T) {
	for _, saved := range []string{"absent", "true", "false"} {
		for _, requested := range []struct {
			value, suffix string
		}{
			{},
			{value: "true", suffix: " --mark-latest=true"},
			{value: "false", suffix: " --mark-latest=false"},
			{value: "no", suffix: " --mark-latest=false"},
		} {
			t.Run("saved="+saved+"/requested="+requested.value, func(t *testing.T) {
				attachments, deploys := 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
						c := containerView{ID: testContainerID, Name: "app", Status: statusStopped, HostName: "inf13", HostID: "h1", VolumeSlots: []volumeSlot{{Name: "data"}}}
						if saved != "absent" {
							value := saved == "true"
							c.MarkLatestRelease = &value
						}
						if err := json.NewEncoder(w).Encode(c); err != nil {
							t.Error(err)
						}
					case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
						io.WriteString(w, testVolumeList(false))
					case r.Method == http.MethodPut && r.URL.Path == "/api/containers/"+testContainerID+"/volumes/data":
						attachments++
						w.WriteHeader(http.StatusConflict)
						io.WriteString(w, `{"error":"volume is already in use"}`)
					case r.Method == http.MethodPost && r.URL.Path == "/api/containers/"+testContainerID+"/deploy":
						deploys++
						io.WriteString(w, `{}`)
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				deployVolumes = []string{"data-vol"}
				deployMarkLatestRelease = requested.value
				containerDeployCmd.Flags().Lookup("mark-latest").Changed = requested.value != ""
				_, err := captureTestStdout(func() error {
					return containerDeployCmd.RunE(containerDeployCmd, []string{testContainerID})
				})
				if err == nil || !strings.Contains(err.Error(), "could not attach data-vol") {
					t.Fatalf("expected attachment failure, got %v", err)
				}
				lines := strings.Split(err.Error(), "\n")
				want := "tinfoil container deploy " + testContainerID + requested.suffix
				if got := strings.TrimSpace(lines[len(lines)-1]); got != want {
					t.Fatalf("recovery command = %q, want %q", got, want)
				}
				if attachments != 1 || deploys != 0 {
					t.Fatalf("attachment failure must not retry or deploy: attachments=%d deploys=%d", attachments, deploys)
				}
			})
		}
	}
}
