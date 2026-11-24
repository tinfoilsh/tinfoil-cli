package cli

import (
	"bytes"
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
	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
	"github.com/tinfoilsh/tinfoil-go/verify"
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

	_, err := resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.ErrorContains(t, err, "requires --config")
	require.ErrorContains(t, commandState.containerConnectCmd.RunE(commandState.containerConnectCmd, []string{testContainerID}), "requires --config")
	commandState.rootOpts.localConfigFile = path
	require.ErrorContains(t, checkLocalConfigDigest(commandState.rootOpts, registryConfigDigest), "does not match")
	target, err := resolveTunnelTarget(testAuthedClient, testStreams(), commandState.forwardOpts, commandState.rootOpts, commandState.trustOpts, testContainerID)
	require.NoError(t, err)
	require.Empty(t, target.pin)
	require.Equal(t, "app.example.com", target.host)
	require.NoError(t, checkLocalConfigDigest(commandState.rootOpts, digest))

	// Replacing the file after checking the descriptor cannot change trust bytes.
	require.NoError(t, os.WriteFile(path, []byte("different config"), 0600))
	opts, err := verificationOptions(commandState.rootOpts, target.pin, "")
	require.NoError(t, err)
	require.True(t, opts.Verifier.CallerAuthorizesConfig())
	cached, err := readLocalConfig(commandState.rootOpts)
	require.NoError(t, err)
	require.Equal(t, data, cached)
	require.ErrorContains(t, func() error {
		_, err := newVerifiedClient(commandState.rootOpts, target.host, repoPin("acme/app"), "")
		return err
	}(), "--config cannot be used with")

	guidance := containerConnectionGuidance(c, false)
	require.Contains(t, guidance, "--config <FILE>")
	require.Contains(t, guidance, "sha256:"+digest)
	require.NotContains(t, guidance, "--repo")
	_, err = containerConnection(c, false, repoPin("acme/app"))
	require.ErrorContains(t, err, "require --config instead")
	c.Source = containerSourceGitHub
	_, err = containerConnection(c, false, verify.Pin{})
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

const (
	// earlierConfigVersion is the last cvm-version whose config stays YAML.
	earlierConfigVersion = "0.15.5-rc.0"
	jsonConfigImage      = "ghcr.io/acme/app@sha256:" + registryConfigDigest
)

var jsonConfigVersion = strings.TrimPrefix(tinfoilconfig.JSONConfigMinVersion, "v")

// yamlConfigFixture is a config as a person writes it, pinning version.
func yamlConfigFixture(version string) string {
	return `# Written by hand.
cvm-version: ` + version + `@sha256:` + registryConfigDigest + `
cpus: 2
memory: 2048
containers:
  - name: app
    image: "` + jsonConfigImage + `"
    cpus: 1.5
    env:
      - PORT: 8080
shim:
  upstream-port: 8080
`
}

// jsonConfigFixture is the JSON config of yamlConfigFixture(version).
func jsonConfigFixture(version string) string {
	return `{"containers":[{"cpus":"1.5","env":[{"PORT":"8080"}],"image":"` + jsonConfigImage + `","name":"app"}],"cpus":2,"cvm-version":"` + version + `@sha256:` + registryConfigDigest + `","memory":2048,"shim":{"upstream-port":8080}}`
}

// indentedConfigFixture is jsonConfigFixture(version) as an editor saves it.
func indentedConfigFixture(version string) string {
	return "{\n\t\"shim\": {\"upstream-port\": 8080},\n\t\"memory\": 2048,\n\t\"cvm-version\": \"" + version + "@sha256:" + registryConfigDigest + "\",\n\t\"cpus\": 2,\n" +
		"\t\"containers\": [{\"name\": \"app\", \"image\": \"" + jsonConfigImage + "\", \"cpus\": \"1.5\", \"env\": [{\"PORT\": \"8080\"}]}]\n}\n"
}

func writeLocalConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tinfoil-config.yml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func translationNotice(path, config string) string {
	return "Translated " + path + " to its JSON config, sha256:" + storageHash([]byte(config)) + "\n"
}

func TestLocalConfigIsReadAsItsJSONConfig(t *testing.T) {
	want := jsonConfigFixture(jsonConfigVersion)
	for _, test := range []struct {
		name       string
		file       string
		want       string
		translated bool
	}{
		{name: "YAML at the first JSON version", file: yamlConfigFixture(jsonConfigVersion), want: want, translated: true},
		{name: "JSON config", file: want, want: want},
		{name: "JSON in another form", file: indentedConfigFixture(jsonConfigVersion), want: want, translated: true},
		{name: "YAML before the first JSON version", file: yamlConfigFixture(earlierConfigVersion), want: yamlConfigFixture(earlierConfigVersion)},
		{name: "JSON before the first JSON version", file: indentedConfigFixture(earlierConfigVersion), want: indentedConfigFixture(earlierConfigVersion)},
		{name: "earlier YAML that the config library refuses", file: yamlConfigFixture(earlierConfigVersion) + "unknown: 1\n", want: yamlConfigFixture(earlierConfigVersion) + "unknown: 1\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notices bytes.Buffer
			rootOpts := &rootOptions{localConfigFile: writeLocalConfig(t, test.file), notices: func() io.Writer { return &notices }}
			data, err := readLocalConfig(rootOpts)
			require.NoError(t, err)
			require.Equal(t, test.want, string(data))

			// The digest check and the embedded config both use the JSON config.
			require.NoError(t, checkLocalConfigDigest(rootOpts, storageHash([]byte(test.want))))
			input, err := verificationInput(rootOpts, verify.Pin{}, "")
			require.NoError(t, err)
			require.Equal(t, test.want, string(input.Config.Bytes()))
			_, err = input.Options()
			require.NoError(t, err)
			if test.translated {
				require.ErrorContains(t, checkLocalConfigDigest(rootOpts, storageHash([]byte(test.file))), "does not match")
				require.Equal(t, translationNotice(rootOpts.localConfigFile, test.want), notices.String())
			} else {
				require.Empty(t, notices.String())
			}
		})
	}
}

func TestLocalConfigRejectsWhatHasNoJSONConfig(t *testing.T) {
	source, config := yamlConfigFixture(jsonConfigVersion), jsonConfigFixture(jsonConfigVersion)
	for name, file := range map[string]string{
		"unknown field":      source + "unknown: 1\n",
		"ambiguous value":    strings.Replace(source, "PORT: 8080", "PORT: 0x50", 1),
		"JSON fraction":      strings.Replace(config, `"cpus":2`, `"cpus":2.5`, 1),
		"JSON null":          strings.Replace(config, `"memory":2048`, `"memory":null`, 1),
		"JSON unknown field": strings.Replace(config, `"memory"`, `"unknown"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var notices bytes.Buffer
			rootOpts := &rootOptions{localConfigFile: writeLocalConfig(t, file), notices: func() io.Writer { return &notices }}
			_, err := readLocalConfig(rootOpts)
			require.ErrorContains(t, err, "invalid config "+rootOpts.localConfigFile)
			require.ErrorContains(t, checkLocalConfigDigest(rootOpts, storageHash([]byte(file))), "invalid config")
			_, err = verificationInput(rootOpts, verify.Pin{}, "")
			require.ErrorContains(t, err, "invalid config")
			require.Empty(t, notices.String())
		})
	}
}

func TestCreateLocalConfigSendsItsJSONConfig(t *testing.T) {
	commandState := newCommandFixture()

	want := jsonConfigFixture(jsonConfigVersion)
	for _, test := range []struct {
		name       string
		file       string
		want       string
		translated bool
	}{
		{name: "YAML at the first JSON version", file: yamlConfigFixture(jsonConfigVersion), want: want, translated: true},
		{name: "JSON config", file: want, want: want},
		{name: "JSON in another form", file: indentedConfigFixture(jsonConfigVersion), want: want, translated: true},
		{name: "YAML before the first JSON version", file: yamlConfigFixture(earlierConfigVersion), want: yamlConfigFixture(earlierConfigVersion)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeLocalConfig(t, test.file)
			var sent []any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
					return
				}
				sent = append(sent, body["config"])
				io.WriteString(w, `{"id":"`+testContainerID+`","name":"app","source":"local","status":"deploying"}`)
			}))
			defer server.Close()
			configureContainerPromotionTest(commandState, t, server.URL)
			commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = "", ""
			stderr, err := captureTestStderr(func() error {
				_, err := captureTestStdout(func() error {
					return executeLifecycleCLI(commandState, t, "container", "create", "app", "--config", path, "--no-wait")
				})
				return err
			})
			require.NoError(t, err)
			require.Equal(t, []any{base64.StdEncoding.EncodeToString([]byte(test.want))}, sent)
			if test.translated {
				require.Equal(t, 1, strings.Count(string(stderr), translationNotice(path, test.want)))
			} else {
				require.NotContains(t, string(stderr), "Translated")
			}
		})
	}

	t.Run("config with no JSON form", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected API request: %s", r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		configureContainerPromotionTest(commandState, t, server.URL)
		commandState.containerCreateOpts.createRepo, commandState.containerCreateOpts.createTag = "", ""
		path := writeLocalConfig(t, yamlConfigFixture(jsonConfigVersion)+"unknown: 1\n")
		require.ErrorContains(t, executeLifecycleCLI(commandState, t, "container", "create", "app", "--config", path, "--no-wait"), "invalid config "+path)
	})
}

func TestSSHReportsATranslatedConfigOnce(t *testing.T) {
	commandState := newCommandFixture()

	configureContainerPromotionTest(commandState, t, "https://unused.example")
	config := jsonConfigFixture(jsonConfigVersion)
	path := writeLocalConfig(t, yamlConfigFixture(jsonConfigVersion))
	var notices bytes.Buffer
	rootOpts := &rootOptions{localConfigFile: path, notices: func() io.Writer { return &notices }}
	_, err := proxyCommand(rootOpts, &tunnelOptions{}, &tunnelTarget{host: "app.example.com"}, defaultSSHPort)
	require.NoError(t, err)
	require.Equal(t, translationNotice(path, config), notices.String())

	// An invalid register stops each command after it reads the config and
	// before it dials the enclave.
	forward := func(mode ...string) string {
		stderr, err := captureTestStderr(func() error {
			return executeLifecycleCLI(commandState, t, append([]string{"forward", "--enclave", "app.example.com", "--config", path, "--sealed-to", "invalid"}, mode...)...)
		})
		require.Error(t, err)
		return string(stderr)
	}
	require.NotContains(t, forward("--stdio", "22"), "Translated")
	require.Contains(t, forward("--local", "8022:22"), translationNotice(path, config))
}
