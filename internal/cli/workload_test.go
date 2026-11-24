package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestReleaseTemplateBindsOnlyParameters(t *testing.T) {
	template := releaseTemplate("0.15.3")
	for _, test := range releaseCases {
		t.Run(test.name, func(t *testing.T) {
			config := changedRelease(t, template, test.changes...)
			if test.direct {
				config += releaseDirectNetwork
			}
			err := renderedRelease([]byte(template), containerView{Repo: test.repo, Config: config})
			if test.message == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.message)
			}
		})
	}
	for name, change := range map[string]releaseChange{
		"number":  {releaseOwnerParameter, "SANDBOX_OWNER_PUBLIC_KEY: 123"},
		"null":    {releaseOwnerParameter, "SANDBOX_OWNER_PUBLIC_KEY:"},
		"boolean": {releaseDirectParameter, "NO_MONITOR: true"},
	} {
		t.Run("parameter bound to a "+name, func(t *testing.T) {
			config := changedRelease(t, template, change)
			require.ErrorContains(t, renderedRelease([]byte(template), containerView{Repo: defaultSandboxRepo, Config: config}), "explicit measured environment")
		})
	}
}
