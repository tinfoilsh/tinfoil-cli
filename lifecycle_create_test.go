package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testReplacedContainerID = "22222222-2222-4222-8222-222222222222"

func TestCreateRejectsInvalidConfigBeforeDiskAdvice(t *testing.T) {
	for _, tt := range []struct {
		name, response, want string
		status               int
	}{
		{"invalid with required mount", `{"valid":false,"config":{"volumes":[{"name":"data","key_secret":"KEY"}]},"errors":[{"field":"cpus","code":"INVALID_CPUS","message":"unsupported CPU count"},{"field":"workflow","message":"missing workflow"}]}`, "cpus [INVALID_CPUS]: unsupported CPU count\n  workflow: missing workflow", http.StatusOK},
		{"invalid without config", `{"valid":false,"errors":[{"field":"workflow","message":"missing workflow"}]}`, "workflow: missing workflow", http.StatusOK},
		{"invalid without errors", `{"valid":false}`, "config validation failed", http.StatusOK},
		{"errors override valid", `{"valid":true,"config":{},"errors":[{"field":"gpus","message":"not entitled"}]}`, "gpus: not entitled", http.StatusOK},
		{"missing config", `{"valid":true}`, "returned no configuration", http.StatusOK},
		{"scoped permission", `{"error":"key lacks permission"}`, "containers.validate permission", http.StatusForbidden},
		{"unauthenticated", `{"error":"invalid admin key"}`, "401: invalid admin key", http.StatusUnauthorized},
	} {
		for _, withVolume := range []bool{false, true} {
			t.Run(tt.name+map[bool]string{false: "/no-disk", true: "/selected-disk"}[withVolume], func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != http.MethodPost || r.URL.Path != "/api/containers/validate" {
						t.Errorf("must not create or look up disks: %s %s", r.Method, r.URL.Path)
					}
					w.WriteHeader(tt.status)
					io.WriteString(w, tt.response)
				}))
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				if withVolume {
					createVolumes = []string{"data-vol"}
				}
				_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("err = %v, want %q", err, tt.want)
				}
				for _, forbidden := range []string{"volume create", "select an existing disk", "container deploy"} {
					if strings.Contains(err.Error(), forbidden) {
						t.Fatalf("invalid config produced disk advice: %v", err)
					}
				}
				if calls != 1 {
					t.Fatalf("calls = %d, want validation only", calls)
				}
			})
		}
	}
}

type createFlowFixture struct {
	mounts            []volumeSlot
	volumes           []volumeView
	replaceStatus     int
	replaceResponseID string
	attachFailureAt   int
	deployStatus      int
	loadFailure       bool
	returnedNoMounts  bool
	paths             []string
	bodies            map[string]map[string]any
	created, deployed bool
	attachments       int
}

func newCreateFlowFixture() *createFlowFixture {
	return &createFlowFixture{
		mounts:  []volumeSlot{{Name: "data", KeySecret: "KEY"}},
		volumes: []volumeView{{ID: testVolumeID, Name: "data-vol", HostID: "h1", HostName: "inf13"}},
		bodies:  map[string]map[string]any{},
	}
}

func (f *createFlowFixture) serve(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.Method + " " + r.URL.Path
		f.paths = append(f.paths, path)
		if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			f.bodies[path] = body
		}
		write := func(value any) {
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		container := containerView{ID: testContainerID, Name: "app", Status: statusStopped, HostName: "inf13", HostID: "h1", VolumeSlots: f.mounts}
		switch {
		case path == "GET /api/containers/"+testReplacedContainerID:
			if f.replaceStatus != 0 {
				w.WriteHeader(f.replaceStatus)
				write(map[string]any{"error": "replacement access denied"})
				return
			}
			replaceID := testReplacedContainerID
			if f.replaceResponseID != "" {
				replaceID = f.replaceResponseID
			}
			write(containerView{ID: replaceID, Name: "old-app", Status: statusRunning, HostID: "h1", HostName: "inf13"})
		case path == "POST /api/containers/validate":
			write(map[string]any{"valid": true, "config": map[string]any{"volumes": f.mounts}})
		case path == "GET /api/volumes":
			if f.deployed && f.loadFailure {
				w.WriteHeader(http.StatusForbidden)
				write(map[string]any{"error": "cannot list volumes"})
				return
			}
			write(volumeList{Volumes: f.volumes})
		case path == "POST /api/containers":
			f.created = true
			if f.returnedNoMounts {
				container.VolumeSlots = nil
			}
			write(container)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/containers/"+testContainerID+"/volumes/"):
			if !f.created {
				t.Error("attached before create")
			}
			f.attachments++
			if f.attachments == f.attachFailureAt {
				w.WriteHeader(http.StatusConflict)
				write(map[string]any{"error": "volume is already attached to another container"})
				return
			}
			for i := range f.volumes {
				if f.volumes[i].ID == f.bodies[path]["volume_id"] {
					f.volumes[i].ContainerID = testContainerID
					f.volumes[i].Slot = strings.TrimPrefix(r.URL.Path, "/api/containers/"+testContainerID+"/volumes/")
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case path == "POST /api/containers/"+testContainerID+"/deploy":
			if !f.created {
				t.Error("deployed before create")
			}
			f.deployed = true
			if f.deployStatus != 0 {
				w.WriteHeader(f.deployStatus)
				write(map[string]any{"error": "host unavailable"})
				return
			}
			container.Status = statusDeploying
			write(container)
		default:
			t.Errorf("unexpected request (no deletes or detaches allowed): %s", path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func TestCreateForwardsReleaseChoiceThroughVolumeDeploy(t *testing.T) {
	for _, mode := range []string{"optional", "attached", "replacement"} {
		for _, mark := range []string{"", "true", "false"} {
			t.Run(mode+"/mark="+mark, func(t *testing.T) {
				f := newCreateFlowFixture()
				if mode == "optional" {
					f.mounts[0].KeySecret = ""
				}
				if mode == "replacement" {
					f.volumes[0].ContainerID = testReplacedContainerID
				}
				server := f.serve(t)
				defer server.Close()
				configureContainerPromotionTest(t, server.URL)
				if mode != "optional" {
					createVolumes = []string{"data-vol"}
				}
				if mode == "replacement" {
					createReplaceID = testReplacedContainerID
				}
				createMarkLatestRelease = mark
				containerCreateCmd.Flags().Lookup("mark-latest").Changed = mark != ""
				_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
				if err != nil {
					t.Fatal(err)
				}
				if !f.created || !f.deployed {
					t.Fatal("create must automatically deploy")
				}
				for _, path := range []string{"POST /api/containers", "POST /api/containers/" + testContainerID + "/deploy"} {
					value, exists := f.bodies[path]["mark_latest_release"]
					if exists != (mark != "") || exists && value != (mark == "true") {
						t.Fatalf("%s body = %v for choice %q", path, f.bodies[path], mark)
					}
				}
				for _, path := range []string{"POST /api/containers/validate", "POST /api/containers"} {
					value, exists := f.bodies[path]["replace_container_id"]
					if exists != (mode == "replacement") || exists && value != testReplacedContainerID {
						t.Fatalf("replacement context missing or incorrect: %v", f.bodies[path])
					}
				}
				if mode != "optional" {
					if f.attachments != 1 || f.bodies["POST /api/containers"]["host_name"] != "inf13" {
						t.Fatal("must attach once on disk's host")
					}
					attachPath := "PUT /api/containers/" + testContainerID + "/volumes/data"
					if f.bodies[attachPath]["volume_id"] != testVolumeID {
						t.Fatalf("attachment wire contract changed: %v", f.bodies[attachPath])
					}
				}
			})
		}
	}
}

func TestCreateRejectsUnsafeDiskAssignmentsBeforeReplacement(t *testing.T) {
	for _, tt := range []struct {
		name       string
		requests   []string
		host, want string
		setup      func(*createFlowFixture)
	}{
		{name: "missing required mount", requests: []string{"data-vol:data"}, setup: func(f *createFlowFixture) {
			f.mounts = append(f.mounts, volumeSlot{Name: "cache", KeySecret: "CACHE_KEY"})
		}, want: `required mount "cache" has no disk`},
		{name: "unknown mount", requests: []string{"data-vol:missing"}, want: `does not declare mount "missing"`},
		{name: "duplicate mount", requests: []string{"data-vol:data", "other:data"}, want: `mount "data" was given twice`},
		{name: "same disk for two mounts", requests: []string{"data-vol:data", testVolumeID + ":cache"}, setup: func(f *createFlowFixture) { f.mounts = append(f.mounts, volumeSlot{Name: "cache"}) }, want: "was selected more than once"},
		{name: "attached to unrelated workload", requests: []string{"data-vol"}, setup: func(f *createFlowFixture) { f.volumes[0].ContainerID = testContainerID }, want: "only disks attached to the explicit --replace target"},
		{name: "host mismatch", requests: []string{"data-vol"}, host: "inf14", want: "--host inf14 does not match"},
		{name: "replacement disk host mismatch", requests: []string{"data-vol"}, setup: func(f *createFlowFixture) {
			f.volumes[0].ContainerID = testReplacedContainerID
			f.volumes[0].HostID = "h2"
		}, want: "does not match replacement target"},
		{name: "mixed hosts", requests: []string{"data-vol:data", "other:cache"}, setup: func(f *createFlowFixture) {
			f.mounts = append(f.mounts, volumeSlot{Name: "cache"})
			f.volumes = append(f.volumes, volumeView{ID: "other-id", Name: "other", HostID: "h2", HostName: "inf14"})
		}, want: "are on different hosts"},
		{name: "replacement permission denied", requests: []string{"data-vol"}, setup: func(f *createFlowFixture) { f.replaceStatus = http.StatusForbidden }, want: "resolve --replace target"},
		{name: "replacement response mismatch", requests: []string{"data-vol"}, setup: func(f *createFlowFixture) { f.replaceResponseID = testContainerID }, want: "unexpected container ID; refusing to replace"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newCreateFlowFixture()
			if tt.setup != nil {
				tt.setup(f)
			}
			server := f.serve(t)
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			createReplaceID, createVolumes, createHost = testReplacedContainerID, tt.requests, tt.host
			_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if f.created || f.attachments != 0 || f.deployed {
				t.Fatalf("unsafe assignment caused mutations: %v", f.paths)
			}
		})
	}
}

func TestCreateWithoutReplacementCannotReuseAttachedDisk(t *testing.T) {
	f := newCreateFlowFixture()
	f.volumes[0].ContainerID = testReplacedContainerID
	server := f.serve(t)
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	createVolumes = []string{"data-vol"}
	_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
	if err == nil || !strings.Contains(err.Error(), "already attached") || f.created {
		t.Fatalf("attached disk accepted without --replace: %v", err)
	}
}

func TestCreatePartialFailuresDescribeRetainedState(t *testing.T) {
	for _, stage := range []string{"attach", "deploy", "load volumes", "changed config"} {
		t.Run(stage, func(t *testing.T) {
			f := newCreateFlowFixture()
			f.volumes[0].ContainerID = testReplacedContainerID
			f.mounts = append(f.mounts, volumeSlot{Name: "cache", KeySecret: "CACHE_KEY"})
			f.volumes = append(f.volumes, volumeView{ID: "other-disk", Name: "cache-vol", HostID: "h1", HostName: "inf13"})
			switch stage {
			case "attach":
				f.attachFailureAt = 2
			case "deploy":
				f.deployStatus = http.StatusServiceUnavailable
			case "load volumes":
				f.loadFailure = true
			case "changed config":
				f.returnedNoMounts = true
			}
			server := f.serve(t)
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			createReplaceID, createVolumes = testReplacedContainerID, []string{"data-vol:data", "cache-vol:cache"}
			createMarkLatestRelease = "false"
			containerCreateCmd.Flags().Lookup("mark-latest").Changed = true
			_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
			if err == nil {
				t.Fatal("expected follow-up failure")
			}
			for _, want := range []string{"created app (" + testContainerID + ")", "replaced container " + testReplacedContainerID + " was removed", "retained", "tinfoil container get " + testContainerID} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error lacks %q: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), "container is stopped") {
				t.Fatalf("cannot claim concurrent state: %v", err)
			}
			if stage == "attach" || stage == "deploy" {
				if !strings.Contains(err.Error(), "tinfoil container deploy "+testContainerID+" --mark-latest=false") {
					t.Fatalf("recovery loses release choice: %v", err)
				}
			}
			if stage == "attach" {
				if f.deployed || f.volumes[0].ContainerID != testContainerID {
					t.Fatal("must retain first attachment and not deploy after second fails")
				}
			}
			if stage == "load volumes" && !strings.Contains(err.Error(), "deploy was accepted (status deploying)") {
				t.Fatalf("error hides accepted deployment: %v", err)
			}
		})
	}
}
