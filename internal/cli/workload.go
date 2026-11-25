package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/selfupdate"
	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
	"github.com/tinfoilsh/tinfoil-config/yamlconfig"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"go.yaml.in/yaml/v3"
)

const (
	releaseTemplateName     = "tinfoil-config.yml"
	releaseTemplateWorkflow = "tinfoil-release-publish.yml"
	releaseImageWorkflow    = "tinfoil-release.yml"
	releaseImageRef         = "refs/heads/main"
	releaseImageRegistry    = "ghcr.io/"
	releaseDirectSettings   = `{"cvm-network": {"inbound-ports": [22]}}`
	releaseCertProxyTLS     = `{"shim": {"tls-mode": "cert-proxy"}}`
	templateEnvPath         = "containers.env."
	templateVolumeSizePath  = "volumes.size"
)

// Keep the checked configuration and its measured bindings together through
// attestation and credential delivery. Never rebuild the source after approval.
type workloadTarget struct {
	containerView
	source verify.Pin
	env    map[string]string
}

// The controlplane supplies the config; tinfoil-go verifies its endorsement and
// measured digest before a connection can carry owner credentials.
func resolveWorkload(streams commandIO, rootOpts *rootOptions, trustOpts *trustOptions, row containerView, repository string, assertion verify.Pin) (*workloadTarget, error) {
	if rootOpts.localConfigFile != "" {
		return nil, errors.New("managed workloads use their published configuration; pin it with --project instead of --config")
	}
	if row.Repo != repository || row.Debug || row.Config == "" {
		return nil, errors.New("unexpected workload configuration")
	}
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return nil, err
	}
	digest := storageHash([]byte(row.Config))
	if !strings.HasSuffix(row.ConfigName, "/"+digest) {
		return nil, errors.New("workload config reference does not match its digest")
	}
	target, err := parseConnectionDescriptor(connectionDescriptor{URL: "https://" + row.Domain, ConfigName: row.ConfigName, ConfigDigest: digest})
	if err != nil {
		return nil, err
	}
	if !trustOpts.trustDangerous {
		check := rootOpts.connections.verifyRelease
		if check == nil {
			check = verifyRelease
		}
		if err := check(row); err != nil {
			return nil, fmt.Errorf("verifying %s as release %s of %s: %w; --dangerous skips this check", row.Name, row.CurrentTag, repository, err)
		}
	}
	if err := trustConnectionSource(streams, trustOpts, target.source, assertion); err != nil {
		return nil, err
	}
	return &workloadTarget{containerView: row, source: target.source, env: env}, nil
}

func verifyRelease(row containerView) error {
	ctx := context.Background()
	template, err := selfupdate.ReleaseAsset(ctx, row.Repo, row.CurrentTag, releaseTemplateName, releaseTemplateWorkflow, configendorsement.MaxConfigSize)
	if err != nil {
		return err
	}
	var release struct{ Containers []struct{ Image string } }
	if err := errors.Join(renderedRelease(template, row), yaml.Unmarshal(template, &release)); err != nil {
		return err
	}
	// A tag can be cut from any commit, so the image must also be built from main.
	for _, container := range release.Containers {
		digest, err := hex.DecodeString(strings.TrimPrefix(container.Image, releaseImageRegistry+row.Repo+"@sha256:"))
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("unexpected image %s", container.Image)
		}
		if err := selfupdate.VerifyProvenance(ctx, row.Repo, releaseImageWorkflow, releaseImageRef, [sha256.Size]byte(digest)); err != nil {
			return fmt.Errorf("image %s: %w", container.Image, err)
		}
	}
	return nil
}

// renderedRelease reports an error unless row's config is the release template
// with only its parameters bound.
func renderedRelease(template []byte, row containerView) error {
	env, err := measuredEnvironment(row.Config)
	if err == nil && isJSONConfig([]byte(row.Config)) {
		return renderedJSONRelease(template, row, env)
	}
	var want, got, direct, certProxy yaml.Node
	if err := errors.Join(err, yaml.Unmarshal(template, &want), yaml.Unmarshal([]byte(row.Config), &got), yaml.Unmarshal([]byte(releaseDirectSettings), &direct), yaml.Unmarshal([]byte(releaseCertProxyTLS), &certProxy)); err != nil {
		return err
	}
	if row.Repo == defaultSandboxRepo && env["NO_MONITOR"] == "1" && len(want.Content) == 1 {
		overlay(want.Content[0], direct.Content[0])
		// Bunkers created before the owner relay still carry cert-proxy.
		if !rendered(&want, &got, "") {
			overlay(want.Content[0], certProxy.Content[0])
		}
	}
	if !rendered(&want, &got, "") {
		return errors.New("its config differs from the release template")
	}
	return nil
}

// renderedJSONRelease is renderedRelease for a row whose config is JSON. The
// release template is YAML, so its translation is what the config must match.
func renderedJSONRelease(template []byte, row containerView, env map[string]string) error {
	translated, err := yamlconfig.ToJSON(template, tinfoilconfig.Options{})
	if err != nil {
		return fmt.Errorf("translating the release template: %w", err)
	}
	var want, got, direct, certProxy map[string]any
	if err := errors.Join(json.Unmarshal(translated, &want), readJSONConfig(row.Config, &got), json.Unmarshal([]byte(releaseDirectSettings), &direct), json.Unmarshal([]byte(releaseCertProxyTLS), &certProxy)); err != nil {
		return err
	}
	if row.Repo == defaultSandboxRepo && env["NO_MONITOR"] == "1" {
		overlayJSON(want, direct)
		// Bunkers created before the owner relay still carry cert-proxy.
		if !renderedJSON(want, got, "") {
			overlayJSON(want, certProxy)
		}
	}
	if !renderedJSON(want, got, "") {
		return errors.New("its config differs from the release template")
	}
	return nil
}

// readJSONConfig decodes a JSON config, which must be in its one byte form so
// that no other reader takes its bytes differently.
func readJSONConfig(raw string, out any) error {
	if err := tinfoilconfig.CheckJSONForm([]byte(raw)); err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	return json.Unmarshal([]byte(raw), out)
}

// rendered reports whether got is the template want with only its parameters bound.
func rendered(want, got *yaml.Node, path string) bool {
	if want.Kind != got.Kind || want.Tag != got.Tag || len(want.Content) != len(got.Content) {
		return false
	}
	parameter := want.Value == "" && strings.HasPrefix(path, templateEnvPath) || path == templateVolumeSizePath
	if want.Value != got.Value && !parameter {
		return false
	}
	for i, child := range want.Content {
		at := path
		if want.Kind == yaml.MappingNode && i%2 == 1 {
			at = strings.TrimPrefix(path+"."+want.Content[i-1].Value, ".")
		}
		if !rendered(child, got.Content[i], at) {
			return false
		}
	}
	return true
}

// renderedJSON is rendered for the values of two JSON configs. Members are
// matched by name, and a parameter is bound to a string.
func renderedJSON(want, got any, path string) bool {
	switch want := want.(type) {
	case map[string]any:
		got, ok := got.(map[string]any)
		if !ok || len(want) != len(got) {
			return false
		}
		for name, value := range want {
			member, ok := got[name]
			if !ok || !renderedJSON(value, member, strings.TrimPrefix(path+"."+name, ".")) {
				return false
			}
		}
		return true
	case []any:
		got, ok := got.([]any)
		if !ok || len(want) != len(got) {
			return false
		}
		for i, item := range want {
			if !renderedJSON(item, got[i], path) {
				return false
			}
		}
		return true
	case string:
		got, ok := got.(string)
		parameter := want == "" && strings.HasPrefix(path, templateEnvPath) || path == templateVolumeSizePath
		return ok && (want == got || parameter)
	}
	return want == got
}

func overlay(node, patch *yaml.Node) {
	if node.Kind != yaml.MappingNode || patch.Kind != yaml.MappingNode {
		*node = *patch
		return
	}
	for i := 0; i < len(patch.Content); i += 2 {
		j := 0
		for j < len(node.Content) && node.Content[j].Value != patch.Content[i].Value {
			j += 2
		}
		if j < len(node.Content) {
			overlay(node.Content[j+1], patch.Content[i+1])
		} else {
			node.Content = append(node.Content, patch.Content[i:i+2]...)
		}
	}
}

// overlayJSON is overlay for the values of JSON configs.
func overlayJSON(node, patch map[string]any) {
	for name, value := range patch {
		existing, mapping := node[name].(map[string]any)
		members, merge := value.(map[string]any)
		if mapping && merge {
			overlayJSON(existing, members)
		} else {
			node[name] = value
		}
	}
}

func missingContainer(err error) bool {
	var missing *cpError
	return errors.As(err, &missing) && missing.Status == http.StatusNotFound
}

func measuredEnvironment(raw string) (map[string]string, error) {
	if isJSONConfig([]byte(raw)) {
		return measuredJSONEnvironment(raw)
	}
	var config struct{ Containers []struct{ Env []yaml.Node } }
	if err := yaml.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, container := range config.Containers {
		for _, entry := range container.Env {
			if entry.Kind == yaml.ScalarNode {
				continue
			}
			if entry.Kind != yaml.MappingNode || len(entry.Content) != 2 || entry.Content[1].Tag != "!!str" {
				return nil, errors.New("workload requires explicit measured environment mappings")
			}
			name, value := entry.Content[0].Value, entry.Content[1].Value
			if _, seen := values[name]; seen {
				return nil, fmt.Errorf("workload environment %s is ambiguous", name)
			}
			values[name] = value
		}
	}
	return values, nil
}

// measuredJSONEnvironment is measuredEnvironment for a JSON config, whose
// literal values are the text a container receives.
func measuredJSONEnvironment(raw string) (map[string]string, error) {
	var config struct {
		Containers []struct {
			Env []jsontext.Value `json:"env"`
		} `json:"containers"`
	}
	if err := readJSONConfig(raw, &config); err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, container := range config.Containers {
		for _, entry := range container.Env {
			if entry.Kind() == jsontext.KindString {
				continue
			}
			var mapping map[string]string
			if json.Unmarshal(entry, &mapping) != nil || len(mapping) != 1 {
				return nil, errors.New("workload requires explicit measured environment mappings")
			}
			for name, value := range mapping {
				if _, seen := values[name]; seen {
					return nil, fmt.Errorf("workload environment %s is ambiguous", name)
				}
				values[name] = value
			}
		}
	}
	return values, nil
}
