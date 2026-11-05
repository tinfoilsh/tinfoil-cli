package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const registryConfigDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCreateRegistryRevision(t *testing.T) {
	commandState := newCommandFixture()

	for _, revision := range []string{"v1.2.3", "sha256:" + registryConfigDigest} {
		t.Run(revision, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				var body map[string]any
				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
					return
				}
				assert.Equal(t, containerSourceRegistry, body["source"])
				assert.Equal(t, "acme/app", body["repo"])
				assert.Equal(t, revision, body["revision"])
				assert.NotContains(t, body, "tag")
				io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","config_name":"/acme/app/v1.2.3","status":"deploying"}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(commandState, t, server.URL)
			commandState.containerCreateOpts.createTag = ""
			output, err := captureTestStdout(func() error {
				return executeLifecycleCLI(commandState, t, "container", "create", "app", "--source", "registry", "--repo", "acme/app", "--revision", revision, "--no-wait")
			})
			require.NoError(t, err)
			require.Equal(t, []string{"POST /api/containers"}, paths)
			require.Contains(t, string(output), `"config_name": "/acme/app/v1.2.3"`)
		})
	}
}

func TestCreateGitHubRevision(t *testing.T) {
	commandState := newCommandFixture()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		var body map[string]any
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
			return
		}
		if r.URL.Path == "/api/containers/validate" {
			assert.Equal(t, "v1.2.3", body["tag"])
			io.WriteString(w, `{"valid":true,"config":{"volumes":[]}}`)
			return
		}
		assert.NotContains(t, body, "source")
		assert.Equal(t, "v1.2.3", body["revision"])
		assert.NotContains(t, body, "tag")
		io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","status":"deploying"}`)
	}))
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	commandState.containerCreateOpts.createTag, commandState.containerCreateOpts.createRevision = "", "v1.2.3"
	_, err := captureTestStdout(func() error {
		return commandState.containerCreateCmd.RunE(commandState.containerCreateCmd, []string{"app"})
	})
	require.NoError(t, err)
	require.Equal(t, []string{"/api/containers/validate", "/api/containers"}, paths)
}

func TestCreateRejectsInvalidSourceSelection(t *testing.T) {
	commandState := newCommandFixture()

	for _, test := range []struct {
		args    []string
		message string
	}{
		{[]string{"--source", "unknown", "--revision", "v1"}, "--source must be"},
		{[]string{"--source", "registry", "--tag", "v1"}, "use --revision"},
		{[]string{"--source", "registry", "--revision", "v1", "--replace", testContainerID}, "registry configs do not support --replace"},
		{[]string{"--source", "registry"}, "at least one of the flags"},
		{[]string{"--tag", "v1", "--revision", "v2"}, "none of the others can be"},
	} {
		t.Run(test.message, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("unexpected API request: %s", r.URL)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			configureContainerPromotionTest(commandState, t, server.URL)
			commandState.containerCreateOpts.createTag = ""
			err := executeLifecycleCLI(commandState, t, append([]string{"container", "create", "app", "--repo", "acme/app"}, test.args...)...)
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestCreateRegistryAttachesVolumesBeforeDeploy(t *testing.T) {
	commandState := newCommandFixture()

	fixture := newCreateFlowFixture()
	fixture.mounts = []volumeSlot{{Name: "data"}}
	server := fixture.serve(t)
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	commandState.containerCreateOpts.createSource, commandState.containerCreateOpts.createTag, commandState.containerCreateOpts.createRevision = containerSourceRegistry, "", "v1.2.3"
	commandState.containerCreateOpts.createVolumes = []string{"data-vol"}
	_, err := captureTestStdout(func() error {
		return commandState.containerCreateCmd.RunE(commandState.containerCreateCmd, []string{"app"})
	})
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
	commandState := newCommandFixture()

	descriptor := connectionDescriptor{URL: "https://app.example.com", ConfigName: "/acme/app/v1.2.3", ConfigDigest: registryConfigDigest}
	expected := "acme/app@v1.2.3@sha256:" + registryConfigDigest
	target, err := parseConnectionDescriptor(descriptor)
	require.NoError(t, err)
	require.Equal(t, expected, target.source)

	for _, invalid := range []connectionDescriptor{
		{URL: descriptor.URL, ConfigName: "/acme/app", ConfigDigest: registryConfigDigest},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName, ConfigDigest: "bad"},
		{URL: descriptor.URL, ConfigName: descriptor.ConfigName, ConfigDigest: registryConfigDigest, Repo: "acme/other"},
	} {
		_, err := parseConnectionDescriptor(invalid)
		require.Error(t, err)
	}

	c := containerView{ID: testContainerID, Name: "app", ConfigName: descriptor.ConfigName, Domain: "app.example.com", Connections: &containerConnections{Production: &descriptor}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/containers/"+testContainerID, r.URL.Path)
		json.NewEncoder(w).Encode(c)
	}))
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	gateEnv(t, `{"allow":{"pins":["acme/app@sha256:`+registryConfigDigest+`"]}}`)
	previousRepo := commandState.rootOpts.repo
	commandState.rootOpts.repo = ""
	t.Cleanup(func() { commandState.rootOpts.repo = previousRepo })
	tunnel, err := resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Equal(t, expected, tunnel.repo)
	require.Equal(t, target.host, tunnel.host)
	require.Contains(t, containerConnectionGuidance(c, false), "--repo "+expected)

	descriptor.ConfigDigest = strings.TrimPrefix(testDigestB, "sha256:")
	_, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "not in your known configs")
	descriptor.ConfigDigest = registryConfigDigest

	commandState.rootOpts.repo = "acme/app@sha256:" + strings.Repeat("a", len(registryConfigDigest))
	tunnel, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Equal(t, commandState.rootOpts.repo, tunnel.repo)
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.True(t, policy.HasPin(commandState.rootOpts.repo), "explicit hash pin must be recorded")

	for _, name := range []string{"", "/acme/other/v1.2.3"} {
		invalid := descriptor
		invalid.ConfigName = name
		if name == "" {
			invalid.Repo, invalid.Tag, invalid.ConfigDigest = "acme/app", "v1.2.3", ""
		}
		c.Connections.Production = &invalid
		_, err := containerConnection(c, false, "")
		require.ErrorContains(t, err, "connection config does not match")
	}
}
