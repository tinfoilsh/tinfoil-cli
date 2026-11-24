package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
)

const (
	releaseOwnerParameter  = `SANDBOX_OWNER_PUBLIC_KEY: ""`
	releaseDirectParameter = `NO_MONITOR: ""`
	releaseVolumeSize      = "size: 30GiB"
	releaseTLSMode         = "tls-mode: self-signed"
	releaseDirectNetwork   = "cvm-network:\n  inbound-ports: [22]\n"
)

// releaseTemplate is a bunker release template that pins version.
func releaseTemplate(version string) string {
	return `# Bunker release template.
cvm-version: ` + version + `@sha256:` + registryConfigDigest + `
cpus: 4
memory: 8192
networks:
  dev:
    egress: open
volumes:
  - name: workspace
    ` + releaseVolumeSize + `
containers:
  - name: workspace
    image: "ghcr.io/` + defaultSandboxRepo + `@sha256:` + registryConfigDigest + `"
    cpus: 1.5
    networks: [dev]
    persistent_volumes: [workspace:/mnt/disk]
    env:
      - ` + releaseOwnerParameter + `
      - ` + releaseDirectParameter + `
      - HOME
shim:
  ` + releaseTLSMode + `
  upstream-port: 8080
  drain_timeout: 5m
`
}

// releaseChange rewrites one line of a release template.
type releaseChange struct{ old, new string }

func changedRelease(t *testing.T, template string, changes ...releaseChange) string {
	t.Helper()
	for _, change := range changes {
		require.Contains(t, template, change.old)
		template = strings.Replace(template, change.old, change.new, 1)
	}
	return template
}

var (
	releaseOwnerBound  = releaseChange{releaseOwnerParameter, `SANDBOX_OWNER_PUBLIC_KEY: "owner-key"`}
	releaseSizeBound   = releaseChange{releaseVolumeSize, `size: "64GB"`}
	releaseDirectBound = releaseChange{releaseDirectParameter, `NO_MONITOR: "1"`}
	releaseCertProxy   = releaseChange{releaseTLSMode, "tls-mode: cert-proxy"}
)

// releaseCases are configs that the control plane could store for a release
// template, and whether each is that template with only its parameters bound.
var releaseCases = []struct {
	name    string
	repo    string
	changes []releaseChange
	direct  bool
	message string
}{
	{name: "unbound template", repo: defaultSandboxRepo},
	{name: "bound parameters", repo: defaultSandboxRepo, changes: []releaseChange{releaseOwnerBound, releaseSizeBound}},
	{name: "direct access", repo: defaultSandboxRepo, changes: []releaseChange{releaseOwnerBound, releaseDirectBound}, direct: true},
	{name: "direct access with the earlier TLS mode", repo: defaultSandboxRepo, changes: []releaseChange{releaseDirectBound, releaseCertProxy}, direct: true},
	{name: "direct access without its port", repo: defaultSandboxRepo, changes: []releaseChange{releaseDirectBound}, message: "differs"},
	{name: "direct port without direct access", repo: defaultSandboxRepo, changes: []releaseChange{releaseOwnerBound}, direct: true, message: "differs"},
	{name: "direct access for another workload", repo: monitorRepo, changes: []releaseChange{releaseDirectBound}, direct: true, message: "differs"},
	{name: "earlier TLS mode without direct access", repo: defaultSandboxRepo, changes: []releaseChange{releaseCertProxy}, message: "differs"},
	{name: "another image", repo: defaultSandboxRepo, changes: []releaseChange{{registryConfigDigest + `"`, strings.Repeat("f", len(registryConfigDigest)) + `"`}}, message: "differs"},
	{name: "open egress to closed", repo: defaultSandboxRepo, changes: []releaseChange{{"egress: open", "egress: closed"}}, message: "differs"},
	{name: "added environment entry", repo: defaultSandboxRepo, changes: []releaseChange{{"      - HOME\n", "      - HOME\n      - EXTRA: \"1\"\n"}}, message: "differs"},
	{name: "bound runtime variable", repo: defaultSandboxRepo, changes: []releaseChange{{"      - HOME\n", "      - HOME: \"/root\"\n"}}, message: "differs"},
	{name: "added container", repo: defaultSandboxRepo, changes: []releaseChange{{"shim:\n", "  - name: extra\n    image: \"ghcr.io/acme/extra@sha256:" + registryConfigDigest + "\"\nshim:\n"}}, message: "differs"},
	{name: "removed volume size", repo: defaultSandboxRepo, changes: []releaseChange{{"    " + releaseVolumeSize + "\n", ""}}, message: "differs"},
	{name: "repeated parameter", repo: defaultSandboxRepo, changes: []releaseChange{{"      - HOME\n", "      - HOME\n      - NO_MONITOR: \"1\"\n"}}, message: "ambiguous"},
}

// storedJSONConfig is what the control plane keeps for a rendered config that
// pins a cvm-version whose config is JSON.
func storedJSONConfig(t *testing.T, rendered string) string {
	t.Helper()
	stored, err := tinfoilconfig.Normalize([]byte(rendered), tinfoilconfig.Options{})
	require.NoError(t, err)
	require.NoError(t, tinfoilconfig.CheckJSONForm(stored))
	return string(stored)
}

func TestReleaseTemplateBindsOnlyParameters(t *testing.T) {
	for _, form := range []struct {
		name    string
		version string
		stored  func(*testing.T, string) string
	}{
		{"YAML", earlierConfigVersion, func(_ *testing.T, rendered string) string { return rendered }},
		{"JSON", jsonConfigVersion, storedJSONConfig},
	} {
		template := releaseTemplate(form.version)
		for _, test := range releaseCases {
			t.Run(form.name+"/"+test.name, func(t *testing.T) {
				config := changedRelease(t, template, test.changes...)
				if test.direct {
					config += releaseDirectNetwork
				}
				err := renderedRelease([]byte(template), containerView{Repo: test.repo, Config: form.stored(t, config)})
				if test.message == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, test.message)
				}
			})
		}
	}
}

func TestYAMLReleaseParametersAreStrings(t *testing.T) {
	template := releaseTemplate(earlierConfigVersion)
	for name, change := range map[string]releaseChange{
		"number":  {releaseOwnerParameter, "SANDBOX_OWNER_PUBLIC_KEY: 123"},
		"null":    {releaseOwnerParameter, "SANDBOX_OWNER_PUBLIC_KEY:"},
		"boolean": {releaseDirectParameter, "NO_MONITOR: true"},
	} {
		t.Run(name, func(t *testing.T) {
			config := changedRelease(t, template, change)
			require.ErrorContains(t, renderedRelease([]byte(template), containerView{Repo: defaultSandboxRepo, Config: config}), "explicit measured environment")
		})
	}
}

func TestJSONReleaseConfigIsComparedByValue(t *testing.T) {
	// A literal the template writes as a YAML number is text in the JSON config.
	template := changedRelease(t, releaseTemplate(jsonConfigVersion), releaseChange{"      - HOME\n", "      - HOME\n      - PORT: 8080\n"})
	stored := storedJSONConfig(t, changedRelease(t, template, releaseOwnerBound, releaseSizeBound))
	require.Contains(t, stored, `{"PORT":"8080"}`)
	require.Contains(t, stored, `"cpus":"1.5"`)
	require.NoError(t, renderedRelease([]byte(template), containerView{Repo: defaultSandboxRepo, Config: stored}))
	env, err := measuredEnvironment(stored)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"SANDBOX_OWNER_PUBLIC_KEY": "owner-key", "NO_MONITOR": "", "PORT": "8080"}, env)

	for _, test := range []struct {
		name    string
		change  releaseChange
		message string
	}{
		{"changed literal", releaseChange{`{"PORT":"8080"}`, `{"PORT":"8081"}`}, "differs"},
		{"changed decimal", releaseChange{`"cpus":"1.5"`, `"cpus":"2.5"`}, "differs"},
		{"changed duration", releaseChange{`"drain_timeout":"5m"`, `"drain_timeout":"6m"`}, "differs"},
		{"changed integer", releaseChange{`"memory":8192`, `"memory":8193`}, "differs"},
		{"integer as text", releaseChange{`"memory":8192`, `"memory":"8192"`}, "differs"},
		{"added member", releaseChange{`"memory":8192`, `"gpus":1,"memory":8192`}, "differs"},
		{"removed member", releaseChange{`"drain_timeout":"5m",`, ``}, "differs"},
		{"runtime variable for a literal", releaseChange{`{"PORT":"8080"}`, `"PORT"`}, "differs"},
		{"parameter bound to a number", releaseChange{`"SANDBOX_OWNER_PUBLIC_KEY":"owner-key"`, `"SANDBOX_OWNER_PUBLIC_KEY":123`}, "explicit measured environment"},
		{"volume size bound to a number", releaseChange{`"size":"64GB"`, `"size":64`}, "differs"},
		{"environment entry with two names", releaseChange{`{"PORT":"8080"}`, `{"A":"1","PORT":"8080"}`}, "explicit measured environment"},
		{"members out of order", releaseChange{`"name":"workspace","size":"64GB"`, `"size":"64GB","name":"workspace"`}, "canonical form"},
		{"indented", releaseChange{`{"containers":`, "{\n  \"containers\":"}, "canonical form"},
		{"null member", releaseChange{`"memory":8192`, `"memory":null`}, "null"},
		{"repeated member", releaseChange{`"memory":8192`, `"memory":8192,"memory":8192`}, `"memory"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := changedRelease(t, stored, test.change)
			require.ErrorContains(t, renderedRelease([]byte(template), containerView{Repo: defaultSandboxRepo, Config: config}), test.message)
		})
	}

	t.Run("template that has no JSON config", func(t *testing.T) {
		ambiguous := changedRelease(t, template, releaseChange{"PORT: 8080", "PORT: 0x50"})
		require.ErrorContains(t, renderedRelease([]byte(ambiguous), containerView{Repo: defaultSandboxRepo, Config: stored}), "translating the release template")
	})
	t.Run("template for an earlier version", func(t *testing.T) {
		earlier := changedRelease(t, template, releaseChange{jsonConfigVersion, earlierConfigVersion})
		require.ErrorContains(t, renderedRelease([]byte(earlier), containerView{Repo: defaultSandboxRepo, Config: stored}), "differs")
	})
}
