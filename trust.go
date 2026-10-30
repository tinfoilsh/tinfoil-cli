package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"go.yaml.in/yaml/v3"
)

// Trusted workload templates are compiled in from each repository's
// tinfoil-config.yml; inventory never supplies a template or build policy.
var (
	//go:embed trusted/monitor-config.yml
	trustedMonitorTemplate []byte
	//go:embed trusted/sandbox-config.yml
	trustedSandboxTemplate []byte
)

const (
	storageCredentialsPath = "/api/deployments/storage-credentials"
	approvedBuildRef       = "refs/heads/main"
	slsaProvenanceV1       = "https://slsa.dev/provenance/v1"
	maxImageBundles        = 16
)

var (
	imageAttestationsAPI = "https://api.github.com/repos"
	monitorBucketPattern = regexp.MustCompile(`^s3://[a-z0-9.-]+\?prefix=containers%2F([0-9a-f]{64})%2F[A-Za-z0-9-]+%2F&region=[a-z0-9-]+$`)
	yamlScalarTags       = []string{"!!str", "!!int", "!!float", "!!bool", "!!null"}
)

// workloadPolicy is a trusted template plus the exact substitutions one resource may make.
type workloadPolicy struct {
	repo       string
	template   []byte
	env        map[string]string
	volumeSize string
}

func monitorPolicy(owner, bucket string) workloadPolicy {
	return workloadPolicy{repo: monitorRepo, template: trustedMonitorTemplate, env: map[string]string{
		monitorOwnerEnv: owner, "TINFOIL_STORAGE_BUCKET": bucket, "AWS_CONTAINER_CREDENTIALS_FULL_URI": fixedAPIOrigin + storageCredentialsPath}}
}

// The NO_MONITOR=1 profile is a separate explicit choice, never a fallback.
func sandboxPolicy(owner, instance, volumeSize string, noMonitor bool) workloadPolicy {
	return workloadPolicy{repo: defaultSandboxRepo, template: trustedSandboxTemplate, volumeSize: volumeSize, env: map[string]string{
		sandboxOwnerEnv: owner, "SANDBOX_INSTANCE_ID": instance, "NO_MONITOR": map[bool]string{false: "", true: "1"}[noMonitor]}}
}

// formatVolumeSize renders a volume capacity as controlplane writes it into a config.
func formatVolumeSize(bytes int64) string {
	if bytes%sizeUnits["gb"] == 0 {
		return strconv.FormatInt(bytes/sizeUnits["gb"], 10) + "GB"
	}
	return strconv.FormatInt(bytes, 10) + "B"
}

// bucketOwnedBy reports whether a Monitor bucket names the storage owner of account and user.
func bucketOwnedBy(bucket, account, user string) bool {
	owner := "org:" + account
	if account == "personal" {
		owner = "user:" + user
	}
	match := monitorBucketPattern.FindStringSubmatch(bucket)
	digest := sha256.Sum256([]byte(owner))
	return match != nil && match[1] == hex.EncodeToString(digest[:])
}

// check compares the complete attested config with the template and returns its
// image digest, whose build provenance must still be verified.
func (p workloadPolicy) check(config []byte) (string, error) {
	template, err := plainYAML(p.template)
	if err != nil {
		return "", err
	}
	attested, err := plainYAML(config)
	if err != nil {
		return "", err
	}
	image := regexp.MustCompile(`^ghcr\.io/` + regexp.QuoteMeta(p.repo) + `@sha256:([0-9a-f]{64})$`)
	var digest string
	err = matchYAML(template, attested, nil, func(path []string, node *yaml.Node) (bool, error) {
		value := node.Value
		if node.Kind != yaml.ScalarNode || node.ShortTag() != "!!str" {
			value = "\x00"
		}
		switch {
		case len(path) == 3 && path[0] == "containers" && path[2] == "image":
			match := image.FindStringSubmatch(value)
			if match == nil || digest != "" && digest != match[1] {
				return true, errors.New("unexpected image")
			}
			digest = match[1]
		case len(path) == 3 && path[0] == "volumes" && path[2] == "size" && p.volumeSize != "":
			if value != p.volumeSize {
				return true, errors.New("the workspace volume size differs from the bound volume")
			}
		case len(path) == 5 && path[0] == "containers" && path[2] == "env":
			want, ok := p.env[path[4]]
			if !ok {
				return false, nil
			}
			if value != want {
				return true, fmt.Errorf("%s differs from the selected resource", path[4])
			}
		default:
			return false, nil
		}
		return true, nil
	})
	if err == nil && digest == "" {
		err = errors.New("no image")
	}
	if err != nil {
		return "", fmt.Errorf("the attested configuration is not an approved %s: %w", p.repo, err)
	}
	return digest, nil
}

// plainYAML accepts only plain YAML: no aliases, anchors, merge keys, duplicate keys or custom tags.
func plainYAML(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("it is not a single plain YAML document")
	}
	var walk func(*yaml.Node) error
	walk = func(node *yaml.Node) error {
		if node.Kind == yaml.AliasNode || node.Anchor != "" {
			return errors.New("it uses YAML aliases")
		}
		switch node.Kind {
		case yaml.MappingNode:
			if node.ShortTag() != "!!map" {
				return errors.New("it uses YAML tags")
			}
			seen := map[string]bool{}
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || seen[key.Value] {
					return errors.New("it has merge, duplicate or non-string keys")
				}
				seen[key.Value] = true
			}
		case yaml.SequenceNode:
			if node.ShortTag() != "!!seq" {
				return errors.New("it uses YAML tags")
			}
		case yaml.ScalarNode:
			if !slices.Contains(yamlScalarTags, node.ShortTag()) {
				return errors.New("it uses YAML tags")
			}
		}
		for _, child := range node.Content {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return doc.Content[0], walk(doc.Content[0])
}

// matchYAML requires attested to equal template except where substitute accepts a value.
func matchYAML(template, attested *yaml.Node, path []string, substitute func([]string, *yaml.Node) (bool, error)) error {
	if handled, err := substitute(path, attested); handled || err != nil {
		return err
	}
	at := strings.Join(path, ".")
	if template.Kind != attested.Kind || template.ShortTag() != attested.ShortTag() || len(template.Content) != len(attested.Content) {
		return fmt.Errorf("%s differs", at)
	}
	switch template.Kind {
	case yaml.ScalarNode:
		if template.Value != attested.Value {
			return fmt.Errorf("%s differs", at)
		}
	case yaml.SequenceNode:
		for i := range template.Content {
			if err := matchYAML(template.Content[i], attested.Content[i], append(slices.Clip(path), strconv.Itoa(i)), substitute); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		values := map[string]*yaml.Node{}
		for i := 0; i < len(attested.Content); i += 2 {
			values[attested.Content[i].Value] = attested.Content[i+1]
		}
		for i := 0; i < len(template.Content); i += 2 {
			key := template.Content[i].Value
			value, ok := values[key]
			if !ok {
				return fmt.Errorf("%s has different fields", at)
			}
			if err := matchYAML(template.Content[i+1], value, append(slices.Clip(path), key), substitute); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p workloadPolicy) authorizer(digest *string) func(collateral.ConfigEndorsement) error {
	return func(config collateral.ConfigEndorsement) error {
		found, err := p.check(config.Config)
		*digest = found
		return err
	}
}

// verifyWorkload fetches fresh attestation from host and accepts it only under p,
// including approved build provenance for the attested image.
func verifyWorkload(ctx context.Context, host string, p workloadPolicy) (*verify.Verification, error) {
	var digest string
	handle, err := enclave.NewHandle(host, "", &enclave.Options{ConfigAuthorizer: p.authorizer(&digest)})
	if err != nil {
		return nil, err
	}
	verified, err := handle.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", host, err)
	}
	return verified, nil
}

// verifyWorkloadDocument verifies relayed attestation evidence for nonce under p.
func verifyWorkloadDocument(ctx context.Context, doc, nonce []byte, p workloadPolicy) (*verify.Verification, error) {
	var digest string
	verifier, err := verify.NewVerifier(verify.WithConfigAuthorizer(p.authorizer(&digest)))
	if err != nil {
		return nil, err
	}
	verified, err := verifier.VerifyV3(doc, nonce, "")
	if err != nil {
		return nil, err
	}
	return verified, nil
}

// verifyImage requires Sigstore provenance for digest from repo's release workflow
// on main, with a transparency-log inclusion proof and a signer bound to its run.
func verifyImage(ctx context.Context, repo, digest string) error {
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size {
		return errors.New("invalid image digest")
	}
	data, err := fetchUpdateData(ctx, http.DefaultClient, imageAttestationsAPI+"/"+repo+"/attestations/sha256:"+digest, version, attestationsLimit)
	if err != nil {
		return fmt.Errorf("no approved build evidence for %s image %s: %w", repo, digest, err)
	}
	var listing struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		return fmt.Errorf("decoding build evidence for %s: %w", repo, err)
	}
	signer := "https://github.com/" + repo + "/.github/workflows/tinfoil-release.yml@" + approvedBuildRef
	identity := certificate.Extensions{RunnerEnvironment: "github-hosted", SourceRepositoryURI: "https://github.com/" + repo,
		SourceRepositoryRef: approvedBuildRef, BuildTrigger: "workflow_dispatch", BuildSignerURI: signer}
	lastErr := errors.New("no attestation")
	for i, attestation := range listing.Attestations {
		if i == maxImageBundles {
			break
		}
		result, err := verifySigstoreBundle(attestation.Bundle, raw, "^"+regexp.QuoteMeta(signer)+"$", identity)
		if err != nil {
			lastErr = err
			continue
		}
		if lastErr = checkImageStatement(result.Statement, result.Signature.Certificate.Extensions, repo, digest); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("%s image %s was not built by an approved release: %w", repo, digest, lastErr)
}

// slsaPredicate is the part of GitHub's SLSA v1 provenance bound to the signing certificate.
type slsaPredicate struct {
	BuildDefinition struct {
		ExternalParameters struct {
			Workflow struct{ Repository, Ref, Path string } `json:"workflow"`
		} `json:"externalParameters"`
		InternalParameters struct {
			GitHub struct {
				EventName         string `json:"event_name"`
				RunnerEnvironment string `json:"runner_environment"`
			} `json:"github"`
		} `json:"internalParameters"`
		ResolvedDependencies []struct {
			Digest struct {
				GitCommit string `json:"gitCommit"`
			} `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			InvocationID string `json:"invocationId"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

// checkImageStatement requires the signed provenance of digest to name the same release
// workflow, commit and run as its verified certificate.
func checkImageStatement(statement *intoto.Statement, cert certificate.Extensions, repo, digest string) error {
	signer := "https://github.com/" + repo + "/.github/workflows/tinfoil-release.yml@" + approvedBuildRef
	subject := slices.ContainsFunc(statement.GetSubject(), func(s *intoto.ResourceDescriptor) bool {
		return s.GetName() == "ghcr.io/"+repo && s.GetDigest()["sha256"] == digest
	})
	if statement.GetPredicateType() != slsaProvenanceV1 || !subject {
		return errors.New("the attestation is not SLSA provenance for this image")
	}
	if len(cert.SourceRepositoryDigest) != 40 || cert.SourceRepositoryDigest != cert.BuildSignerDigest ||
		!strings.HasPrefix(cert.RunInvocationURI, "https://github.com/"+repo+"/actions/runs/") {
		return errors.New("the build certificate does not identify its commit and run")
	}
	raw, err := json.Marshal(statement.GetPredicate().AsMap())
	if err != nil {
		return err
	}
	var p slsaPredicate
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	workflow, github := p.BuildDefinition.ExternalParameters.Workflow, p.BuildDefinition.InternalParameters.GitHub
	if workflow.Repository != "https://github.com/"+repo || workflow.Ref != approvedBuildRef || workflow.Path != ".github/workflows/tinfoil-release.yml" ||
		github.EventName != "workflow_dispatch" || github.RunnerEnvironment != "github-hosted" ||
		len(p.BuildDefinition.ResolvedDependencies) == 0 || p.BuildDefinition.ResolvedDependencies[0].Digest.GitCommit != cert.SourceRepositoryDigest ||
		p.RunDetails.Builder.ID != signer || p.RunDetails.Metadata.InvocationID != cert.RunInvocationURI {
		return errors.New("the signed provenance names another workflow, commit or run than its certificate")
	}
	return nil
}
