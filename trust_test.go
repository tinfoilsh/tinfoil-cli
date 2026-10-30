package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const testImageDigest = "1111111111111111111111111111111111111111111111111111111111111111"

// rendered substitutes values into a trusted template the way controlplane renders a
// config, then applies edits to the rendered text.
func rendered(template []byte, substitutions, edits []string) []byte {
	text := regexp.MustCompile(`(image: "ghcr\.io/[^@]+)@sha256:[0-9a-f]{64}`).ReplaceAllString(string(template), "${1}@sha256:"+testImageDigest)
	return []byte(strings.NewReplacer(edits...).Replace(strings.NewReplacer(substitutions...).Replace(text)))
}

func TestWorkloadProfilesAcceptOnlyTheirSubstitutions(t *testing.T) {
	owner, other := ed25519PublicKeyString(testSeed(t)), ed25519PublicKeyString(testSeed(t))
	bucket := "s3://tinfoil-agents?prefix=containers%2F" + strings.Repeat("a", 64) + "%2Fstorage-1%2F&region=us-east-1"
	credentials := fixedAPIOrigin + storageCredentialsPath
	monitor := func(edits ...string) []byte {
		return rendered(trustedMonitorTemplate, []string{
			`MONITOR_OWNER_PUBLIC_KEY: ""`, `MONITOR_OWNER_PUBLIC_KEY: "` + owner + `"`,
			`TINFOIL_STORAGE_BUCKET: ""`, `TINFOIL_STORAGE_BUCKET: "` + bucket + `"`,
			`AWS_CONTAINER_CREDENTIALS_FULL_URI: ""`, `AWS_CONTAINER_CREDENTIALS_FULL_URI: "` + credentials + `"`}, edits)
	}
	policy := monitorPolicy(owner, bucket)
	digest, err := policy.check(monitor())
	require.NoError(t, err)
	require.Equal(t, testImageDigest, digest)
	_, err = policy.check(append(monitor(), []byte("\n# comments do not change the measured meaning\n")...))
	require.NoError(t, err)
	for name, config := range map[string][]byte{
		"changed command":         monitor("- -connector-workers\n", "- -connector-workers\n      - -debug\n"),
		"extra container":         append(monitor(), []byte("  - name: extra\n    image: \"ghcr.io/evil/x@sha256:"+testImageDigest+"\"\n")...),
		"extra environment":       monitor(`      - AWS_CONTAINER_CREDENTIALS_FULL_URI`, "      - EXTRA: \"1\"\n      - AWS_CONTAINER_CREDENTIALS_FULL_URI"),
		"another owner":           monitor(owner, other),
		"another bucket":          monitor("storage-1", "storage-2"),
		"another credentials URL": monitor(credentials, "https://evil.example"+storageCredentialsPath),
		"swapped attested key":    monitor("key: ed25519", "key: ecdsa-p256"),
		"privilege change":        monitor("cvm_admin: true", "cvm_admin: false"),
		"another image repo":      monitor("ghcr.io/tinfoilsh/confidential-agent-monitor", "ghcr.io/tinfoilsh/confidential-agent-sandbox"),
		"YAML alias":              append([]byte("x: &a 1\ny: *a\n"), monitor()...),
		"duplicate key":           append(monitor(), []byte("cpus: 2\n")...),
		"custom tag":              monitor("cpus: 2", "cpus: !custom 2"),
	} {
		require.NotEqual(t, string(monitor()), string(config), name)
		_, err := policy.check(config)
		require.Error(t, err, name)
	}

	instance := "22222222-2222-4222-8222-222222222222"
	sandbox := func(size string, edits ...string) []byte {
		return rendered(trustedSandboxTemplate, []string{
			`SANDBOX_OWNER_PUBLIC_KEY: ""`, `SANDBOX_OWNER_PUBLIC_KEY: "` + owner + `"`,
			`SANDBOX_INSTANCE_ID: ""`, `SANDBOX_INSTANCE_ID: "` + instance + `"`,
			"size: 30GiB", "size: " + size}, edits)
	}
	newVolume, reused := formatVolumeSize(16_000_000_000), formatVolumeSize(30<<30)
	require.Equal(t, "16GB", newVolume)
	require.Equal(t, "32212254720B", reused)
	for _, size := range []string{newVolume, reused} {
		_, err := sandboxPolicy(owner, instance, size, false).check(sandbox(size))
		require.NoError(t, err, "a sandbox opens with its bound volume's rendered size %s", size)
	}
	direct := sandbox(newVolume, `NO_MONITOR: ""`, `NO_MONITOR: "1"`)
	_, err = sandboxPolicy(owner, instance, newVolume, true).check(direct)
	require.NoError(t, err, "the explicit NO_MONITOR=1 profile")
	for name, test := range map[string]struct {
		config []byte
		policy workloadPolicy
	}{
		"changed volume":              {sandbox("32GB"), sandboxPolicy(owner, instance, newVolume, false)},
		"NO_MONITOR in monitored use": {direct, sandboxPolicy(owner, instance, newVolume, false)},
		"monitored in direct use":     {sandbox(newVolume), sandboxPolicy(owner, instance, newVolume, true)},
		"another instance":            {sandbox(newVolume), sandboxPolicy(owner, "33333333-3333-4333-8333-333333333333", newVolume, false)},
		"another owner":               {sandbox(newVolume), sandboxPolicy(other, instance, newVolume, false)},
		"changed executable pack":     {sandbox(newVolume, "sandbox-toolchain@", "evil-toolchain@"), sandboxPolicy(owner, instance, newVolume, false)},
		"missing sandbox-ehbp key":    {sandbox(newVolume, "keys: [host-ssh, sandbox-ehbp]", "keys: [host-ssh]"), sandboxPolicy(owner, instance, newVolume, false)},
		"changed entrypoint port":     {sandbox(newVolume, "'22:22'", "'2222:22'"), sandboxPolicy(owner, instance, newVolume, false)},
	} {
		if strings.HasPrefix(name, "changed") || strings.HasPrefix(name, "missing") {
			require.NotEqual(t, string(sandbox(newVolume)), string(test.config), name)
		}
		_, err := test.policy.check(test.config)
		require.Error(t, err, name)
	}

	personal, org := sha256.Sum256([]byte("user:user_owner")), sha256.Sum256([]byte("org:org_b"))
	forPersonal := strings.Replace(bucket, strings.Repeat("a", 64), hex.EncodeToString(personal[:]), 1)
	forOrg := strings.Replace(bucket, strings.Repeat("a", 64), hex.EncodeToString(org[:]), 1)
	require.True(t, bucketOwnedBy(forPersonal, "personal", "user_owner"))
	require.True(t, bucketOwnedBy(forOrg, "org_b", "user_owner"))
	require.False(t, bucketOwnedBy(forOrg, "personal", "user_owner"))
	require.False(t, bucketOwnedBy(forPersonal+"&x=1", "personal", "user_owner"))
}

func TestImageProvenanceRequiresTheApprovedReleaseBuild(t *testing.T) {
	listing, err := os.ReadFile("testdata/public-template-attestation.json")
	require.NoError(t, err)
	// This is real public evidence for a sandbox config file, signed by the publish workflow at a tag.
	const configDigest = "5e87c44a08d9452a7a6d4ecca6f6273b899cf19f4f4048cf0e59c3848f9776f7"
	var parsed struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	require.NoError(t, json.Unmarshal(listing, &parsed))
	raw, err := hex.DecodeString(configDigest)
	require.NoError(t, err)
	publish := `^https://github\.com/tinfoilsh/confidential-agent-sandbox/\.github/workflows/tinfoil-release-publish\.yml@refs/tags/v0\.1\.27$`
	_, err = verifySigstoreBundle(parsed.Attestations[0].Bundle, raw, publish, certificate.Extensions{RunnerEnvironment: "github-hosted"})
	require.NoError(t, err, "the shared verifier checks real Sigstore evidence and its inclusion proof")
	var bundle map[string]any
	require.NoError(t, json.Unmarshal(parsed.Attestations[0].Bundle, &bundle))
	envelope := bundle["dsseEnvelope"].(map[string]any)
	statement, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
	require.NoError(t, err)
	envelope["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(statement), "tinfoil-config.yml", "tinfoil-config.yaml", 1)))
	tampered, err := json.Marshal(bundle)
	require.NoError(t, err)
	_, err = verifySigstoreBundle(tampered, raw, publish, certificate.Extensions{RunnerEnvironment: "github-hosted"})
	require.Error(t, err, "a changed statement no longer matches its signature")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Empty(t, r.Header.Get("Authorization"), "evidence is fetched without credentials")
		if r.URL.Path != "/"+defaultSandboxRepo+"/attestations/sha256:"+configDigest {
			http.NotFound(w, r)
			return
		}
		w.Write(listing)
	}))
	defer server.Close()
	previous := imageAttestationsAPI
	imageAttestationsAPI = server.URL
	t.Cleanup(func() { imageAttestationsAPI = previous })
	err = verifyImage(t.Context(), defaultSandboxRepo, configDigest)
	require.ErrorContains(t, err, "not built by an approved release", "a valid attestation from another workflow is not image provenance")
	require.ErrorContains(t, verifyImage(t.Context(), defaultSandboxRepo, testImageDigest), "no approved build evidence")
	require.ErrorContains(t, verifyImage(t.Context(), monitorRepo, configDigest), "no approved build evidence", "evidence is looked up only under the fixed repository")
	require.Equal(t, 3, requests)
	require.ErrorContains(t, verifyImage(t.Context(), defaultSandboxRepo, "not-a-digest"), "invalid image digest")
	require.Equal(t, 3, requests)
}

func TestImageStatementMustNameTheCertificateRun(t *testing.T) {
	repo, commit := monitorRepo, strings.Repeat("a", 40)
	run := "https://github.com/" + repo + "/actions/runs/42/attempts/1"
	signer := "https://github.com/" + repo + "/.github/workflows/tinfoil-release.yml@refs/heads/main"
	cert := certificate.Extensions{SourceRepositoryDigest: commit, BuildSignerDigest: commit, RunInvocationURI: run}
	statement := func(edit func(map[string]any)) *intoto.Statement {
		predicate := map[string]any{
			"buildDefinition": map[string]any{
				"externalParameters":   map[string]any{"workflow": map[string]any{"repository": "https://github.com/" + repo, "ref": "refs/heads/main", "path": ".github/workflows/tinfoil-release.yml"}},
				"internalParameters":   map[string]any{"github": map[string]any{"event_name": "workflow_dispatch", "runner_environment": "github-hosted"}},
				"resolvedDependencies": []any{map[string]any{"digest": map[string]any{"gitCommit": commit}}},
			},
			"runDetails": map[string]any{"builder": map[string]any{"id": signer}, "metadata": map[string]any{"invocationId": run}},
		}
		if edit != nil {
			edit(predicate)
		}
		value, err := structpb.NewStruct(predicate)
		require.NoError(t, err)
		return &intoto.Statement{PredicateType: slsaProvenanceV1, Predicate: value,
			Subject: []*intoto.ResourceDescriptor{{Name: "ghcr.io/" + repo, Digest: map[string]string{"sha256": testImageDigest}}}}
	}
	require.NoError(t, checkImageStatement(statement(nil), cert, repo, testImageDigest))
	at := func(path ...string) func(map[string]any, any) {
		return func(p map[string]any, value any) {
			for _, key := range path[:len(path)-1] {
				p = p[key].(map[string]any)
			}
			p[path[len(path)-1]] = value
		}
	}
	for name, edit := range map[string]func(map[string]any){
		"workflow repository": func(p map[string]any) {
			at("buildDefinition", "externalParameters", "workflow", "repository")(p, "https://github.com/evil/fork")
		},
		"workflow ref": func(p map[string]any) {
			at("buildDefinition", "externalParameters", "workflow", "ref")(p, "refs/heads/dev")
		},
		"workflow path": func(p map[string]any) {
			at("buildDefinition", "externalParameters", "workflow", "path")(p, ".github/workflows/other.yml")
		},
		"event": func(p map[string]any) { at("buildDefinition", "internalParameters", "github", "event_name")(p, "push") },
		"runner": func(p map[string]any) {
			at("buildDefinition", "internalParameters", "github", "runner_environment")(p, "self-hosted")
		},
		"commit": func(p map[string]any) {
			at("buildDefinition", "resolvedDependencies")(p, []any{map[string]any{"digest": map[string]any{"gitCommit": strings.Repeat("b", 40)}}})
		},
		"no dependencies": func(p map[string]any) { at("buildDefinition", "resolvedDependencies")(p, []any{}) },
		"builder": func(p map[string]any) {
			at("runDetails", "builder", "id")(p, "https://github.com/evil/fork/.github/workflows/tinfoil-release.yml@refs/heads/main")
		},
		"run": func(p map[string]any) {
			at("runDetails", "metadata", "invocationId")(p, "https://github.com/"+repo+"/actions/runs/43/attempts/1")
		},
	} {
		require.Error(t, checkImageStatement(statement(edit), cert, repo, testImageDigest), name)
	}
	other := statement(nil)
	other.Subject[0].Name = "ghcr.io/" + defaultSandboxRepo
	require.Error(t, checkImageStatement(other, cert, repo, testImageDigest), "subject of another repository")
	require.Error(t, checkImageStatement(statement(nil), cert, repo, strings.Repeat("2", 64)), "another digest")
	mismatched := cert
	mismatched.BuildSignerDigest = strings.Repeat("c", 40)
	require.Error(t, checkImageStatement(statement(nil), mismatched, repo, testImageDigest), "signer commit differs from source")
	foreignRun := cert
	foreignRun.RunInvocationURI = "https://github.com/evil/fork/actions/runs/42/attempts/1"
	require.Error(t, checkImageStatement(statement(nil), foreignRun, repo, testImageDigest), "run of another repository")
}
