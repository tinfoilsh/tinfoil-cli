package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestParseSize(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    int64
		wantErr string
	}{
		{in: "16TiB", want: 16 << 40},
		{in: "30 GiB", want: 30 << 30},
		{in: "512MiB", want: 512 << 20},
		{in: "1.5GiB", want: 3 << 29},
		{in: "16gib", want: 16 << 30},
		{in: "1TB", want: 1e12},
		{in: "1GB", want: 1e9},
		{in: "512MB", want: 512e6},
		{in: "1073741824", want: 1 << 30},
		{in: "4096B", want: 4096},
		{in: "1.5GB", wantErr: "multiple of 512"},
		{in: "1000", wantErr: "multiple of 512"},
		{in: "0", wantErr: "must be positive"},
		{in: "1.1TiB", wantErr: "whole number of bytes"},
		{in: "16 pebibytes", wantErr: "units are"},
		{in: "TiB", wantErr: "invalid size"},
		{in: "", wantErr: "invalid size"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSize(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseSize(%q) error = %v, want containing %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSize(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	for _, tt := range []struct {
		in   int64
		want string
	}{
		{16 << 40, "16 TiB"},
		{30 << 30, "30 GiB"},
		{3 << 29, "1.5 GiB"},
		{1536, "1.5 KiB"},
		{1e12, "931.3 GiB"},
		{512, "512 B"},
		{0, "0 B"},
	} {
		if got := formatSize(tt.in); got != tt.want {
			t.Errorf("formatSize(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveVolume(t *testing.T) {
	volumes := []volumeView{
		{ID: "11111111-1111-1111-1111-111111111111", Name: "data", HostName: "inf13", SizeBytes: 16 << 40},
		{ID: "22222222-2222-2222-2222-222222222222", Name: "data", HostName: "inf14", SizeBytes: 30 << 30},
		{ID: "33333333-3333-3333-3333-333333333333", Name: "scratch", HostName: "inf13", SizeBytes: 1 << 30},
	}
	for _, tt := range []struct {
		name       string
		identifier string
		wantID     string
		wantErr    []string
	}{
		{name: "by id", identifier: "33333333-3333-3333-3333-333333333333", wantID: "33333333-3333-3333-3333-333333333333"},
		{name: "by unique name", identifier: "scratch", wantID: "33333333-3333-3333-3333-333333333333"},
		{name: "by id when names collide", identifier: "22222222-2222-2222-2222-222222222222", wantID: "22222222-2222-2222-2222-222222222222"},
		{name: "ambiguous name", identifier: "data", wantErr: []string{
			`multiple volumes named "data"; use the volume ID`,
			"11111111-1111-1111-1111-111111111111  16 TiB on inf13",
			"22222222-2222-2222-2222-222222222222  30 GiB on inf14",
		}},
		{name: "unknown name", identifier: "missing", wantErr: []string{`no volume named "missing"`}},
		{name: "unknown id", identifier: "44444444-4444-4444-4444-444444444444", wantErr: []string{"no volume with ID 44444444-4444-4444-4444-444444444444"}},
		{name: "empty", identifier: "  ", wantErr: []string{"volume identifier is empty"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v, err := resolveVolume(volumes, tt.identifier)
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("resolveVolume(%q) = %v, want error", tt.identifier, v)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveVolume(%q): %v", tt.identifier, err)
			}
			if v.ID != tt.wantID {
				t.Fatalf("resolveVolume(%q).ID = %s, want %s", tt.identifier, v.ID, tt.wantID)
			}
		})
	}
}

const (
	testContainerID = "61bd4a3e-5b48-4320-9215-0c7a7f974979"
	testVolumeID    = "0f0e0d0c-0b0a-4908-8706-050403020100"
)

func testVolumeRow(attached bool) string {
	row := `{"id":"` + testVolumeID + `","name":"data-vol","host_id":"h1","host_name":"inf13","size_bytes":17592186044416,"created_at":"2026-09-21T10:00:00Z"`
	if attached {
		row += `,"container_id":"` + testContainerID + `","container_name":"app","slot":"data"`
	}
	return row + `}`
}

func testVolumeList(attached bool) string {
	return `{"volumes":[` + testVolumeRow(attached) + `],"allocated_storage_bytes":17592186044416,"max_storage_bytes":35184372088832,"available_storage_bytes":17592186044416}`
}

func TestVolumeAttachSlotSelection(t *testing.T) {
	for _, tt := range []struct {
		name      string
		as        string
		slots     string
		putStatus int
		wantOut   string
		wantErr   string
		wantPut   bool
	}{
		{name: "defaults to the only declared volume", slots: `[{"name":"data"}]`, wantOut: `Attached data-vol to app as "data"`, wantPut: true},
		{name: "explicit --as", as: "cache", slots: `[{"name":"data"},{"name":"cache"}]`, wantOut: `Attached data-vol to app as "cache"`, wantPut: true},
		{name: "several declared without --as", slots: `[{"name":"data"},{"name":"cache"}]`, wantErr: "declares several volumes (data, cache); pick one with --as"},
		{name: "undeclared --as", as: "logs", slots: `[{"name":"data"}]`, wantErr: `does not declare volume "logs" (declared: data)`},
		{name: "none declared", slots: `[]`, wantErr: "declares no volumes in tinfoil-config.yml"},
		{name: "server refusal passes through", slots: `[{"name":"data"}]`, putStatus: http.StatusConflict, wantErr: "409: stop the container before changing volume assignments", wantPut: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var puts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
					_, _ = io.WriteString(w, testVolumeList(false))
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
					_, _ = io.WriteString(w, `[{"id":"`+testContainerID+`","name":"app","status":"stopped"}]`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
					_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"stopped","host_name":"inf13","volume_slots":`+tt.slots+`}`)
				case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/containers/"+testContainerID+"/volumes/"):
					puts.Add(1)
					body, _ := io.ReadAll(r.Body)
					if got, want := strings.TrimSpace(string(body)), `{"volume_id":"`+testVolumeID+`"}`; got != want {
						t.Errorf("attach body = %s, want %s", got, want)
					}
					if tt.putStatus != 0 {
						w.WriteHeader(tt.putStatus)
						_, _ = io.WriteString(w, `{"error":"stop the container before changing volume assignments"}`)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			configureVolumeTest(t, server.URL)
			volumeAttachAs = tt.as
			out, err := captureTestStdout(func() error {
				return volumeAttachCmd.RunE(volumeAttachCmd, []string{"data-vol", "app"})
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("attach: %v", err)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Fatalf("output %q does not contain %q", out, tt.wantOut)
			}
			if got := puts.Load() > 0; got != tt.wantPut {
				t.Fatalf("attach request made = %v, want %v", got, tt.wantPut)
			}
		})
	}
}

func TestContainerCreateWithVolume(t *testing.T) {
	for _, tt := range []struct {
		name         string
		volumes      []string
		host         string
		slots        string
		attachStatus int
		wantOut      []string
		wantErr      string
		wantPaths    []string
	}{
		{
			name:    "attaches then starts",
			volumes: []string{"data-vol"},
			wantOut: []string{"Status:       Deploying", "Volumes:      data ← data-vol (16 TiB)"},
			wantPaths: []string{
				"GET /api/volumes",
				"POST /api/containers",
				"PUT /api/containers/" + testContainerID + "/volumes/data",
				"POST /api/containers/" + testContainerID + "/deploy",
				"GET /api/volumes",
			},
		},
		{
			name:         "attach failure leaves the container stopped",
			volumes:      []string{"data-vol"},
			attachStatus: http.StatusConflict,
			wantErr: "created app but could not attach data-vol: stop the container before changing volume assignments. The container is stopped; run:\n" +
				"  tinfoil volume attach data-vol app\n" +
				"  tinfoil container deploy app",
			wantPaths: []string{
				"GET /api/volumes",
				"POST /api/containers",
				"PUT /api/containers/" + testContainerID + "/volumes/data",
			},
		},
		{
			name:      "--host must match the volume's host",
			volumes:   []string{"data-vol"},
			host:      "inf14",
			wantErr:   "--host inf14 does not match volume data-vol on host inf13",
			wantPaths: []string{"GET /api/volumes"},
		},
		{
			name:      "--volume is not applied when the config declares no slots",
			volumes:   []string{"data-vol"},
			slots:     `[]`,
			wantErr:   "created app but it declares no volumes in tinfoil-config.yml; --volume was not applied",
			wantPaths: []string{"GET /api/volumes", "POST /api/containers"},
		},
		{
			name: "without --volume refuses before creating anything",
			host: "inf13",
			wantErr: "the config declares volume \"data\"; create a disk for it and pass --volume:\n" +
				"  tinfoil volume create app-data --size <SIZE> --host inf13\n" +
				"  tinfoil container create app ... --volume app-data:data",
			wantPaths: []string{"POST /api/containers/validate"},
		},
		{
			name:      "without --volume and a config with no slots creates normally",
			slots:     `[]`,
			wantOut:   []string{"Status:       Stopped"},
			wantPaths: []string{"POST /api/containers/validate", "POST /api/containers"},
		},
		{
			name:    "without --volume an optional slot creates and deploys",
			slots:   `[{"name":"scratch"}]`,
			wantOut: []string{"Status:       Deploying"},
			wantPaths: []string{
				"POST /api/containers/validate",
				"POST /api/containers",
				"POST /api/containers/" + testContainerID + "/deploy",
				"GET /api/volumes",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			slots := tt.slots
			if slots == "" {
				slots = `[{"name":"data","key_secret":"DATA_KEY"}]`
			}
			var attached atomic.Bool
			var mu sync.Mutex
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.Method+" "+r.URL.Path)
				mu.Unlock()
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers/validate":
					_, _ = io.WriteString(w, `{"valid":true,"config":{"volumes":`+slots+`}}`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
					_, _ = io.WriteString(w, testVolumeList(attached.Load()))
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers":
					body, _ := io.ReadAll(r.Body)
					if len(tt.volumes) > 0 && !strings.Contains(string(body), `"host_name":"inf13"`) {
						t.Errorf("create body %s lacks the volume's host", body)
					}
					_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"stopped","host_name":"inf13","volume_slots":`+slots+`}`)
				case r.Method == http.MethodPut && r.URL.Path == "/api/containers/"+testContainerID+"/volumes/data":
					if tt.attachStatus != 0 {
						w.WriteHeader(tt.attachStatus)
						_, _ = io.WriteString(w, `{"error":"stop the container before changing volume assignments"}`)
						return
					}
					attached.Store(true)
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers/"+testContainerID+"/deploy":
					_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"deploying","host_name":"inf13","volume_slots":`+slots+`}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			configureContainerPromotionTest(t, server.URL)
			outputFormat = "table"
			createVolumes, createHost = tt.volumes, tt.host
			out, err := captureTestStdout(func() error {
				return containerCreateCmd.RunE(containerCreateCmd, []string{"app"})
			})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("create: %v", err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(string(out), want) {
					t.Fatalf("output does not contain %q:\n%s", want, out)
				}
			}
			mu.Lock()
			got := strings.Join(paths, "\n")
			mu.Unlock()
			if want := strings.Join(tt.wantPaths, "\n"); got != want {
				t.Fatalf("requests:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestContainerStartWithVolume(t *testing.T) {
	const slots = `[{"name":"data","key_secret":"DATA_KEY"}]`
	for _, tt := range []struct {
		name      string
		host      string
		wantErr   string
		wantPaths []string
	}{
		{
			name:    "volume host must match the container's host",
			wantErr: "container app is on host inf14 but volume data-vol is on inf13; volumes must be on the container's host",
			wantPaths: []string{
				"GET /api/containers",
				"GET /api/containers/" + testContainerID,
				"GET /api/volumes",
			},
		},
		{
			name: "--host can move the container onto the volume's host",
			host: "inf13",
			wantPaths: []string{
				"GET /api/containers",
				"GET /api/containers/" + testContainerID,
				"GET /api/volumes",
				"PUT /api/containers/" + testContainerID + "/volumes/data",
				"POST /api/containers/" + testContainerID + "/deploy",
				"GET /api/volumes",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attached atomic.Bool
			var mu sync.Mutex
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.Method+" "+r.URL.Path)
				mu.Unlock()
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers":
					_, _ = io.WriteString(w, `[{"id":"`+testContainerID+`","name":"app","status":"stopped","host_name":"inf14"}]`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/containers/"+testContainerID:
					_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"stopped","host_name":"inf14","volume_slots":`+slots+`}`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
					_, _ = io.WriteString(w, testVolumeList(attached.Load()))
				case r.Method == http.MethodPut && r.URL.Path == "/api/containers/"+testContainerID+"/volumes/data":
					attached.Store(true)
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && r.URL.Path == "/api/containers/"+testContainerID+"/deploy":
					body, _ := io.ReadAll(r.Body)
					if tt.host != "" && !strings.Contains(string(body), `"host_name":"`+tt.host+`"`) {
						t.Errorf("start body %s lacks host_name %s", body, tt.host)
					}
					_, _ = io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"deploying","host_name":"inf13","volume_slots":`+slots+`}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			configureContainerPromotionTest(t, server.URL)
			outputFormat = "table"
			deployVolumes, deployHost = []string{"data-vol"}, tt.host
			if tt.host != "" {
				containerDeployCmd.Flags().Lookup("host").Changed = true
			}
			_, err := captureTestStdout(func() error {
				return containerDeployCmd.RunE(containerDeployCmd, []string{"app"})
			})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("start: %v", err)
			}
			mu.Lock()
			got := strings.Join(paths, "\n")
			mu.Unlock()
			if want := strings.Join(tt.wantPaths, "\n"); got != want {
				t.Fatalf("requests:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestVolumeDeleteConfirmation(t *testing.T) {
	for _, tt := range []struct {
		name       string
		attached   bool
		yes        bool
		wantErr    string
		wantOut    string
		wantDelete bool
	}{
		{name: "attached volume is refused before the prompt", attached: true, yes: true, wantErr: "volume data-vol is attached to app; detach it first: tinfoil volume detach data-vol"},
		{name: "prompt cannot be answered without a terminal", wantErr: "deleting a volume requires interactive confirmation; pass --yes to skip the prompt"},
		{name: "--yes deletes", yes: true, wantOut: "Deleted volume data-vol", wantDelete: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
					_, _ = io.WriteString(w, testVolumeList(tt.attached))
				case r.Method == http.MethodDelete && r.URL.Path == "/api/volumes/"+testVolumeID:
					deletes.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			configureVolumeTest(t, server.URL)
			volumeYes = tt.yes
			out, err := captureTestStdout(func() error {
				return volumeDeleteCmd.RunE(volumeDeleteCmd, []string{"data-vol"})
			})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("delete: %v", err)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Fatalf("output %q does not contain %q", out, tt.wantOut)
			}
			if got := deletes.Load() > 0; got != tt.wantDelete {
				t.Fatalf("delete request made = %v, want %v", got, tt.wantDelete)
			}
		})
	}
}

func configureVolumeTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv(envCPURL, serverURL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing-config.json"))
	previousOutput := outputFormat
	previousAs, previousYes := volumeAttachAs, volumeYes
	outputFormat = "table"
	volumeAttachAs, volumeYes = "", false
	t.Cleanup(func() {
		outputFormat = previousOutput
		volumeAttachAs, volumeYes = previousAs, previousYes
	})
}
