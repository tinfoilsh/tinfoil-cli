package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const registryConfigDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCreateRegistryRevision(t *testing.T) {
	for _, revision := range []string{"v1.2.3", "sha256:" + registryConfigDigest} {
		t.Run(revision, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				var body map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.Equal(t, containerSourceRegistry, body["source"])
				require.Equal(t, "acme/app", body["repo"])
				require.Equal(t, revision, body["revision"])
				require.NotContains(t, body, "tag")
				io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","config_name":"/acme/app/v1.2.3","status":"deploying"}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			createTag = ""
			output, err := captureTestStdout(func() error {
				return executeLifecycleCLI(t, "container", "create", "app", "--source", "registry", "--repo", "acme/app", "--revision", revision, "--no-wait")
			})
			require.NoError(t, err)
			require.Equal(t, []string{"POST /api/containers"}, paths)
			require.Contains(t, string(output), `"config_name": "/acme/app/v1.2.3"`)
		})
	}
}

func TestCreateGitHubRevision(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		if r.URL.Path == "/api/containers/validate" {
			require.Equal(t, "v1.2.3", body["tag"])
			io.WriteString(w, `{"valid":true,"config":{"volumes":[]}}`)
			return
		}
		require.NotContains(t, body, "source")
		require.Equal(t, "v1.2.3", body["revision"])
		require.NotContains(t, body, "tag")
		io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"deploying"}`)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	createTag, createRevision = "", "v1.2.3"
	_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
	require.NoError(t, err)
	require.Equal(t, []string{"/api/containers/validate", "/api/containers"}, paths)
}

func TestCreateRejectsInvalidSourceSelection(t *testing.T) {
	for _, test := range []struct{ source, tag, revision, message string }{
		{"unknown", "", "v1", "--source must be"},
		{containerSourceRegistry, "v1", "", "use --revision"},
		{containerSourceRegistry, "", "", "--revision is required"},
		{containerSourceGitHub, "v1", "v2", "cannot be supplied together"},
	} {
		t.Run(test.message, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("unexpected API request: %s", r.URL)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			configureContainerPromotionTest(t, server.URL)
			createSource, createTag, createRevision = test.source, test.tag, test.revision
			err := containerCreateCmd.RunE(containerCreateCmd, []string{"app"})
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestCreateRegistryAttachesVolumesBeforeDeploy(t *testing.T) {
	fixture := newCreateFlowFixture()
	fixture.mounts = []volumeSlot{{Name: "data"}}
	server := fixture.serve(t)
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	createSource, createTag, createRevision = containerSourceRegistry, "", "v1.2.3"
	createVolumes = []string{"data-vol"}
	_, err := captureTestStdout(func() error { return containerCreateCmd.RunE(containerCreateCmd, []string{"app"}) })
	require.NoError(t, err)
	require.Equal(t, []string{
		"GET /api/volumes",
		"POST /api/containers",
		"PUT /api/containers/" + testContainerID + "/volumes/data",
		"POST /api/containers/" + testContainerID + "/deploy",
		"GET /api/volumes",
	}, fixture.paths)
}

func TestRegistryConnectionPinsNameAndDigest(t *testing.T) {
	descriptor := connectionDescriptor{URL: "https://app.example.com", ConfigName: "/acme/app/v1.2.3", ConfigDigest: registryConfigDigest}
	expected := "acme/app@v1.2.3@sha256:" + registryConfigDigest
	target, err := parseConnectionDescriptor(descriptor)
	require.NoError(t, err)
	require.Equal(t, expected, target.source)
	secure, err := newVerifiedClient(target.host, target.source, "")
	require.NoError(t, err)
	require.Equal(t, expected, secure.Repo())

	for _, invalid := range []connectionDescriptor{
		{URL: descriptor.URL, ConfigName: "/acme/app", ConfigDigest: registryConfigDigest},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName},
		{URL: descriptor.URL, ConfigDigest: registryConfigDigest},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName, ConfigDigest: "bad"},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName, ConfigDigest: registryConfigDigest, Repo: "acme/other"},
	} {
		_, err := parseConnectionDescriptor(invalid)
		require.Error(t, err)
	}

	c := containerView{ID: testContainerID, Name: "app", ConfigName: descriptor.ConfigName, Domain: "app.example.com", Connections: &containerConnections{Production: &descriptor}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/containers/"+testContainerID, r.URL.Path)
		json.NewEncoder(w).Encode(c)
	}))
	defer server.Close()
	configureContainerPromotionTest(t, server.URL)
	previousRepo := repo
	repo = ""
	t.Cleanup(func() { repo = previousRepo })
	tunnel, err := resolveTunnelTarget(testContainerID)
	require.NoError(t, err)
	require.Equal(t, expected, tunnel.repo)
	require.Equal(t, target.host, tunnel.host)
	require.Contains(t, containerConnectionGuidance(c, false), "--repo "+expected)

	repo = "acme/app@sha256:" + strings.Repeat("a", len(registryConfigDigest))
	tunnel, err = resolveTunnelTarget(testContainerID)
	require.NoError(t, err)
	require.Equal(t, repo, tunnel.repo)
}
