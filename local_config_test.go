package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func localConfigFixture(t *testing.T) (string, []byte, string) {
	t.Helper()
	data := []byte("# Private config; preserve exact bytes.\ncvm-version: 0.15.1-rc.1@sha256:" + registryConfigDigest + "\n")
	path := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(path, data, 0600))
	digest := sha256.Sum256(data)
	return path, data, hex.EncodeToString(digest[:])
}

func TestCreateLocalConfig(t *testing.T) {
	commandState := newCommandFixture()

	for _, explicitSource := range []bool{false, true} {
		t.Run(boolText(explicitSource), func(t *testing.T) {
			path, data, _ := localConfigFixture(t)
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				var body map[string]any
				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
					return
				}
				assert.Equal(t, containerSourceLocal, body["source"])
				assert.Equal(t, base64.StdEncoding.EncodeToString(data), body["config"])
				assert.NotContains(t, body, "repo")
				assert.NotContains(t, body, "tag")
				assert.NotContains(t, body, "revision")
				io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","source":"local","status":"deploying"}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(commandState, t, server.URL)
			commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = "", ""
			args := []string{"container", "create", "app", "--config", path, "--no-wait"}
			if explicitSource {
				args = append(args, "--source", containerSourceLocal)
			}
			output, err := captureTestStdout(func() error { return executeLifecycleCLI(commandState, t, args...) })
			require.NoError(t, err)
			require.Equal(t, []string{"POST /api/containers"}, paths)
			require.Contains(t, string(output), `"source": "local"`)
		})
	}
}

func TestCreateLocalConfigRejectsUnsupportedSelections(t *testing.T) {
	commandState := newCommandFixture()

	for _, test := range []struct {
		args    []string
		message string
	}{
		{[]string{"--repo", "acme/app"}, "none of the others can be"},
		{[]string{"--public-registry"}, "none of the others can be"},
		{[]string{"--tag", "v1"}, "none of the others can be"},
		{[]string{"--revision", "v1"}, "none of the others can be"},
		{[]string{"--source", containerSourceGitHub}, "--config requires --source local"},
		{[]string{"--source", containerSourceRegistry}, "--config requires --source local"},
		{[]string{"--replace", testContainerID}, "local configs do not support --replace"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("unexpected API request: %s", r.URL)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			configureContainerPromotionTest(commandState, t, server.URL)
			commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = "", ""
			path, _, _ := localConfigFixture(t)
			args := append([]string{"container", "create", "app", "--config", path}, test.args...)
			require.ErrorContains(t, executeLifecycleCLI(commandState, t, args...), test.message)
		})
	}
}

func TestLocalConnectionRequiresTrustedFile(t *testing.T) {
	commandState := newCommandFixture()

	path, data, digest := localConfigFixture(t)
	descriptor := connectionDescriptor{URL: "https://app.example.com", ConfigDigest: digest}
	c := containerView{ID: testContainerID, Name: "app", Source: containerSourceLocal, Domain: "app.example.com", Connections: &containerConnections{Production: &descriptor}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/containers/"+testContainerID, r.URL.Path)
		json.NewEncoder(w).Encode(c)
	}))
	defer server.Close()
	configureContainerPromotionTest(commandState, t, server.URL)
	previousRepo := commandState.rootOpts.repo
	commandState.rootOpts.repo = ""
	t.Cleanup(func() { commandState.rootOpts.repo = previousRepo })

	_, err := resolveTunnelTarget(commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "requires --config")
	require.ErrorContains(t, commandState.containerConnectCmd.RunE(commandState.containerConnectCmd, []string{testContainerID}), "requires --config")
	commandState.rootOpts.localConfigFile = path
	require.ErrorContains(t, checkLocalConfigDigest(commandState.rootOpts, registryConfigDigest), "does not match")
	target, err := resolveTunnelTarget(commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Empty(t, target.repo)
	require.Equal(t, "app.example.com", target.host)
	require.NoError(t, checkLocalConfigDigest(commandState.rootOpts, digest))

	// Replacing the file after checking the descriptor cannot change trust bytes.
	require.NoError(t, os.WriteFile(path, []byte("different config"), 0600))
	opts, err := verificationOptions(commandState.rootOpts, target.repo, "")
	require.NoError(t, err)
	require.True(t, opts.Verifier.CallerAuthorizesConfig())
	cached, err := readLocalConfig(commandState.rootOpts)
	require.NoError(t, err)
	require.Equal(t, data, cached)
	require.ErrorContains(t, func() error {
		_, err := newVerifiedClient(commandState.rootOpts, target.host, "acme/app", "")
		return err
	}(), "cannot be used together")

	guidance := containerConnectionGuidance(c, false)
	require.Contains(t, guidance, "--config <FILE>")
	require.Contains(t, guidance, "sha256:"+digest)
	require.NotContains(t, guidance, "--repo")
	_, err = containerConnection(c, false, "acme/app")
	require.ErrorContains(t, err, "require --config instead")
	c.Source = containerSourceGitHub
	_, err = containerConnection(c, false, "")
	require.ErrorContains(t, err, "source does not match")
}

func TestLocalConnectionRejectsMalformedDescriptors(t *testing.T) {
	for _, descriptor := range []connectionDescriptor{
		{ConfigDigest: "bad"},
		{ConfigDigest: strings.ToUpper(registryConfigDigest)},
		{ConfigDigest: registryConfigDigest, Repo: "acme/app"},
		{ConfigDigest: registryConfigDigest, Tag: "v1"},
	} {
		descriptor.URL = "https://app.example.com"
		_, err := parseConnectionDescriptor(descriptor)
		require.ErrorContains(t, err, "invalid local config reference")
	}
}

func TestLocalConfigFileValidation(t *testing.T) {
	commandState := newCommandFixture()

	configureContainerPromotionTest(commandState, t, "https://unused.example")
	commandState.containerCreateOpts.createSource, commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = containerSourceLocal, "", ""
	require.ErrorContains(t, commandState.containerCreateCmd.RunE(commandState.containerCreateCmd, []string{"app"}), "requires --config")
	commandState.rootOpts.localConfigFile = filepath.Join(t.TempDir(), "missing.yml")
	_, err := readLocalConfig(commandState.rootOpts)
	require.ErrorContains(t, err, "reading config")
	require.NoError(t, os.WriteFile(commandState.rootOpts.localConfigFile, nil, 0600))
	_, err = readLocalConfig(commandState.rootOpts)
	require.ErrorContains(t, err, "config must contain")
}

func TestSSHProxyPreservesLocalConfigPath(t *testing.T) {
	commandState := newCommandFixture()

	configureContainerPromotionTest(commandState, t, "https://unused.example")
	path, data, _ := localConfigFixture(t)
	commandState.rootOpts.localConfigFile = filepath.Join(filepath.Dir(path), "local config 'quoted'.yaml")
	require.NoError(t, os.Rename(path, commandState.rootOpts.localConfigFile))
	proxy, err := proxyCommand(commandState.rootOpts, commandState.tunnelOpts, &tunnelTarget{host: "app.example.com"}, defaultSSHPort)
	require.NoError(t, err)
	command := exec.Command("sh", "-c", "set -- "+proxy+"; printf '%s\\n' \"$@\"")
	command.Dir = t.TempDir()
	out, err := command.Output()
	require.NoError(t, err)
	args := strings.Split(strings.TrimSpace(string(out)), "\n")
	flag := slices.Index(args, "--config")
	require.GreaterOrEqual(t, flag, 0)
	require.Less(t, flag+1, len(args))
	require.Equal(t, commandState.rootOpts.localConfigFile, args[flag+1])
	forwarded, err := os.ReadFile(args[flag+1])
	require.NoError(t, err)
	require.Equal(t, data, forwarded)
	require.NotContains(t, args, "--repo")
}
