package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	storageYAMLIndent           = 2
	storageVolumeWorkloadPrefix = "volume-"
)

var storageTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

type storageArtifactOptions struct {
	Project        string
	Mount          string
	Tag            string
	Domain         string
	ConfigFile     string
	ConfigOut      string
	PolicyFile     string
	PolicyOut      string
	ExistingSecret string
}

func (o storageArtifactOptions) validate(p storageProfile) error {
	if o.Project == "" || o.Mount == "" || o.Tag == "" || o.ConfigFile == "" || o.ConfigOut == "" || o.PolicyOut == "" {
		return fmt.Errorf("--project, --mount, --tag, --config-file, --config-out, and --policy-out are required")
	}
	if !storageTagPattern.MatchString(o.Tag) || strings.Contains(o.Tag, "..") {
		return fmt.Errorf("--tag must be an exact release tag, not a wildcard")
	}
	if err := validateStorageDomain(o.Domain); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	paths := []string{o.ConfigFile, o.ConfigOut, o.PolicyFile, o.PolicyOut}
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[abs] {
			return fmt.Errorf("config/policy input and output paths must be distinct")
		}
		seen[abs] = true
	}
	return nil
}

func storageYAML(raw []byte) (*yaml.Node, error) {
	var doc, extra yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid YAML input")
	}
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("YAML must be a mapping")
	}
	if err := validateStorageYAML(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func validateStorageYAML(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return fmt.Errorf("ambiguous YAML mapping (duplicate, merge, or non-string key)")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validateStorageYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func storageYAMLField(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func storageYAMLString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return ""
	}
	return n.Value
}

func storageScalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func addStorageField(n *yaml.Node, key string, value *yaml.Node) {
	n.Content = append(n.Content, storageScalar(key), value)
}

func ensureStorageString(n *yaml.Node, key, value string) error {
	old := storageYAMLField(n, key)
	if old != nil {
		if storageYAMLString(old) != value {
			return fmt.Errorf("refusing to overwrite existing %s; review the original configuration", key)
		}
		return nil
	}
	addStorageField(n, key, storageScalar(value))
	return nil
}

func encodeStorageYAML(doc *yaml.Node) ([]byte, error) {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(storageYAMLIndent)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encoding prepared YAML failed")
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("finishing prepared YAML failed")
	}
	return out.Bytes(), nil
}

func prepareVolumeConfig(raw []byte, endpoint, mount, ref string, existing bool) ([]byte, string, error) {
	doc, err := storageYAML(raw)
	if err != nil {
		return nil, "", err
	}
	root := doc.Content[0]
	if err := ensureStorageString(root, "keyserver-url", endpoint); err != nil {
		return nil, "", err
	}
	if debug := storageYAMLField(root, "debug"); debug != nil && (debug.Kind != yaml.ScalarNode || debug.Tag != "!!bool" || !strings.EqualFold(debug.Value, "false")) {
		return nil, "", fmt.Errorf("private auto-unlock requires debug: false")
	}
	volumes := storageYAMLField(root, "volumes")
	if volumes == nil || volumes.Kind != yaml.SequenceNode {
		return nil, "", fmt.Errorf("config must declare the selected mount in volumes")
	}
	var selected *yaml.Node
	seen := map[string]bool{}
	for _, volume := range volumes.Content {
		name := storageYAMLString(storageYAMLField(volume, "name"))
		if volume.Kind != yaml.MappingNode || name == "" || seen[name] {
			return nil, "", fmt.Errorf("ambiguous volume declarations")
		}
		seen[name] = true
		if name == mount {
			selected = volume
		}
	}
	if selected == nil {
		return nil, "", fmt.Errorf("selected mount is not declared in config")
	}
	if old := storageYAMLField(selected, "key-secret"); old != nil && existing {
		ref = storageYAMLString(old)
		if !plannedSecretName.MatchString(ref) {
			return nil, "", fmt.Errorf("existing key-secret is not a valid reference")
		}
	}
	if err := ensureStorageString(selected, "key-secret", ref); err != nil {
		return nil, "", err
	}
	for _, volume := range volumes.Content {
		if volume != selected && storageYAMLString(storageYAMLField(volume, "key-secret")) == ref {
			return nil, "", fmt.Errorf("key-secret is shared with another disk; use a reviewed volume-specific release configuration")
		}
	}
	out, err := encodeStorageYAML(doc)
	return out, ref, err
}

func storageReleaseWorkloadName(r storageReceipt) (string, error) {
	identity, err := json.Marshal(struct {
		Repo   string `json:"repo"`
		Tag    string `json:"tag"`
		Domain string `json:"domain"`
	}{Repo: r.Profile.Scope.Repo, Tag: r.Tag, Domain: r.Domain})
	if err != nil {
		return "", fmt.Errorf("encoding release policy identity: %w", err)
	}
	return storageVolumeWorkloadPrefix + r.VolumeID + "-" + storageHash(identity), nil
}

func prepareVolumePolicy(raw []byte, r storageReceipt, secretPath string) ([]byte, error) {
	if !storageRepoPattern.MatchString(r.Profile.Scope.Repo) || !storageTagPattern.MatchString(r.Tag) || !plannedSecretName.MatchString(r.KeySecret) || !looksLikeUUID(r.VolumeID) || !storageNamePattern.MatchString(secretPath) {
		return nil, fmt.Errorf("policy requires exact repository, release, volume, and secret identities")
	}
	if err := validateStorageDomain(r.Domain); err != nil {
		return nil, err
	}
	fragment := len(raw) == 0
	if fragment {
		raw = []byte("workloads: {}\n")
	}
	doc, err := storageYAML(raw)
	if err != nil {
		return nil, err
	}
	workloads := storageYAMLField(doc.Content[0], "workloads")
	if workloads == nil || workloads.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("policy must contain a workloads mapping")
	}
	if fragment {
		workloads.Style = 0
	}
	pins := map[string]bool{}
	var selected *yaml.Node
	for i := 0; i < len(workloads.Content); i += 2 {
		w := workloads.Content[i+1]
		repo := storageYAMLString(storageYAMLField(w, "repo"))
		tag := storageYAMLString(storageYAMLField(w, "tag"))
		domain := storageYAMLString(storageYAMLField(w, "domain"))
		pin := repo + "@" + tag
		if w.Kind != yaml.MappingNode || !storageRepoPattern.MatchString(repo) || !storageTagPattern.MatchString(tag) || pins[pin] {
			return nil, fmt.Errorf("ambiguous policy: each repo/tag must occur exactly once")
		}
		if err := validateStorageDomain(domain); err != nil {
			return nil, fmt.Errorf("policy requires exact domain pins for every workload")
		}
		refs := storageYAMLField(w, "secrets")
		if refs == nil || refs.Kind != yaml.MappingNode || len(refs.Content) == 0 {
			return nil, fmt.Errorf("each existing policy workload must map secrets")
		}
		for j := 0; j < len(refs.Content); j += 2 {
			mapping := refs.Content[j+1]
			if !plannedSecretName.MatchString(refs.Content[j].Value) || mapping.Kind != yaml.MappingNode || storageYAMLString(storageYAMLField(mapping, "path")) == "" || storageYAMLString(storageYAMLField(mapping, "field")) == "" {
				return nil, fmt.Errorf("existing policy contains an invalid secret mapping")
			}
		}
		pins[pin] = true
		if repo == r.Profile.Scope.Repo && tag == r.Tag {
			if domain != r.Domain {
				return nil, fmt.Errorf("this keyserver allows only one domain per repo/tag; choose a distinct released configuration or separate keyserver")
			}
			selected = w
		}
	}
	if selected == nil {
		name := storageVolumeWorkloadPrefix + r.VolumeID
		if storageYAMLField(workloads, name) != nil {
			name, err = storageReleaseWorkloadName(r)
			if err != nil {
				return nil, err
			}
			if storageYAMLField(workloads, name) != nil {
				return nil, fmt.Errorf("release-specific workload name already exists with a different approval; refusing to overwrite")
			}
		}
		selected = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		addStorageField(selected, "repo", storageScalar(r.Profile.Scope.Repo))
		addStorageField(selected, "tag", storageScalar(r.Tag))
		addStorageField(selected, "domain", storageScalar(r.Domain))
		addStorageField(selected, "secrets", &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
		addStorageField(workloads, name, selected)
	}
	secrets := storageYAMLField(selected, "secrets")
	if secrets == nil || secrets.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("policy secrets must be a mapping")
	}
	if old := storageYAMLField(secrets, r.KeySecret); old != nil {
		if old.Kind != yaml.MappingNode || storageYAMLString(storageYAMLField(old, "path")) != secretPath || storageYAMLString(storageYAMLField(old, "field")) != storageSecretField {
			return nil, fmt.Errorf("refusing to overwrite existing policy secret mapping")
		}
	} else {
		ref := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		addStorageField(ref, "path", storageScalar(secretPath))
		addStorageField(ref, "field", storageScalar(storageSecretField))
		addStorageField(secrets, r.KeySecret, ref)
	}
	return encodeStorageYAML(doc)
}

func readStorageInput(path string) ([]byte, error) {
	raw, err := readConfigInput(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read local artifact input")
	}
	return []byte(raw), nil
}

type storageArtifact struct {
	path string
	data []byte
}

func preflightStorageArtifacts(artifacts []storageArtifact) error {
	var missing []string
	for _, artifact := range artifacts {
		matches, err := storageArtifactMatches(artifact.path, artifact.data)
		if err != nil {
			return err
		}
		if !matches {
			missing = append(missing, artifact.path)
		}
	}
	for _, path := range missing {
		if err := probeStorageDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("artifact output directory is not writable: %w", err)
		}
	}
	return nil
}

func storageArtifactMatches(path string, data []byte) (bool, error) {
	old, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(old, data) {
			return true, nil
		}
		return false, fmt.Errorf("output already exists with different contents; choose a new output path")
	}
	if !os.IsNotExist(err) {
		return false, fmt.Errorf("cannot inspect output path")
	}
	return false, nil
}

func writeStorageArtifact(path string, data []byte) error {
	matches, err := storageArtifactMatches(path, data)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	if err := writeStorageFile(path, data, true); err != nil {
		return fmt.Errorf("writing prepared artifact: %w", err)
	}
	return nil
}
