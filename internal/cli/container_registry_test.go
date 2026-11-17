package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const registryConfigDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCreateRegistryRevision(t *testing.T) {
	commandState := newCommandFixture()

	for _, test := range []struct {
		revision string
		source   []string
	}{
		{"v1.2.3", []string{"--source", "registry", "--repo", "acme/app"}},
		{"sha256:" + registryConfigDigest, []string{"--project", "acme/app"}},
	} {
		revision, source := test.revision, test.source
		t.Run(revision, func(t *testing.T) {
			trustPath := gateEnv(t, "")
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
				return executeLifecycleCLI(commandState, t, append([]string{"container", "create", "app", "--revision", revision, "--no-wait"}, source...)...)
			})
			require.NoError(t, err)
			policy, err := loadConnectionPolicyFrom(trustPath)
			require.NoError(t, err)
			require.Equal(t, []string{"acme/app"}, policy.Allow.Projects)
			require.Empty(t, policy.GitHub)
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
	require.Equal(t, projectPin(expected), target.source)

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
	previous := *commandState.rootOpts
	commandState.rootOpts.repo, commandState.rootOpts.project = "", ""
	t.Cleanup(func() { *commandState.rootOpts = previous })
	tunnel, err := resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Equal(t, projectPin(expected), tunnel.pin)
	require.Equal(t, target.host, tunnel.host)
	require.Contains(t, containerConnectionGuidance(c, false), "--project "+expected)

	descriptor.ConfigDigest = strings.TrimPrefix(testDigestB, "sha256:")
	_, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "not in your known configs")
	descriptor.ConfigDigest = registryConfigDigest

	commandState.rootOpts.repo = "acme/app"
	_, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "is a registry project; state it with --project instead of --repo")
	commandState.rootOpts.repo = "acme"
	_, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "state it with --project instead of --repo")

	commandState.rootOpts.repo, commandState.rootOpts.project = "", "acme/app@sha256:"+strings.Repeat("a", len(registryConfigDigest))
	tunnel, err = resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Equal(t, commandState.rootOpts.pin(), tunnel.pin)
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.True(t, policy.HasPin(commandState.rootOpts.pin()), "explicit hash pin must be recorded")
	require.Empty(t, policy.GitHub)

	for _, name := range []string{"", "/acme/other/v1.2.3"} {
		invalid := descriptor
		invalid.ConfigName = name
		if name == "" {
			invalid.Repo, invalid.Tag, invalid.ConfigDigest = "acme/app", "v1.2.3", ""
		}
		c.Connections.Production = &invalid
		_, err := containerConnection(c, false, verify.Pin{})
		require.ErrorContains(t, err, "connection config does not match")
	}
}

func TestTunnelTargetTakesNamespaceFromContainerSource(t *testing.T) {
	commandState := newCommandFixture()

	c := containerView{ID: testContainerID, Name: "app", Repo: "acme/app", Domain: "app.example.com"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(c) }))
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	gateEnv(t, `{"allow":{"projects":["acme/app"]}}`)
	previous := *commandState.rootOpts
	commandState.rootOpts.repo, commandState.rootOpts.project = "", ""
	t.Cleanup(func() { *commandState.rootOpts = previous })
	resolve := func() (*tunnelTarget, error) {
		return resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	}

	_, err := resolve()
	require.ErrorContains(t, err, "Pass --repo acme/app", "a registry project entry must not cover the GitHub repository")
	commandState.rootOpts.project = "acme/app"
	_, err = resolve()
	require.ErrorContains(t, err, "is a GitHub repository; state it with --repo instead of --project")
	commandState.rootOpts.repo = "acme/app@v1"
	tunnel, err := resolve()
	require.NoError(t, err)
	require.Equal(t, repoPin("acme/app@v1"), tunnel.pin)

	c.Source = containerSourceRegistry
	commandState.rootOpts.repo, commandState.rootOpts.project = "", ""
	tunnel, err = resolve()
	require.NoError(t, err)
	require.Equal(t, projectPin("acme/app"), tunnel.pin)
}
