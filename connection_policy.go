package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"go.yaml.in/yaml/v3"
)

// The known-configs store holds the caller's side of connection verification:
// which registry references this user has chosen to trust, at the granularity
// they wrote them down — whole orgs, projects (any revision), or exact pins.
//
// The pins bucket doubles as a journal: every successful connect records the
// exact reference it resolved to (deduplicated, never on --dangerous). A pin
// not yet present is announced as new.
const (
	envKnownConfigs          = "TINFOIL_KNOWN_CONFIGS"
	connectionPolicyFileName = "known-configs.yml"

	// mode: what happens when a descriptor matches no allow entry.
	policyModePrompt = "prompt" // ask yes/no; yes records at the configured granularity
	policyModeFrozen = "frozen" // fail closed; the file changes only by hand

	// record granularity: what a prompt-yes writes.
	policyRecordOrg     = "org"     // everything in the org
	policyRecordProject = "project" // any revision of the project
	policyRecordPin     = "pin"     // the exact reference
)

var policyRecordBuckets = map[string]string{
	policyRecordOrg:     "orgs",
	policyRecordProject: "projects",
	policyRecordPin:     "pins",
}

type connectionPolicy struct {
	Mode     string
	Record   string
	Orgs     []string
	Projects []string
	Pins     []string

	// doc is the YAML tree edits operate on, so hand-written comments
	// survive writes. nil until a file is loaded or the first edit builds a
	// fresh tree in memory.
	doc  *yaml.Node
	path string
}

func connectionPolicyPath() (string, error) {
	if p := os.Getenv(envKnownConfigs); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".tinfoil", connectionPolicyFileName), nil
}

func validateMode(mode string) error {
	switch mode {
	case policyModePrompt, policyModeFrozen:
		return nil
	default:
		return fmt.Errorf("unknown mode %q (valid: %s, %s)", mode, policyModePrompt, policyModeFrozen)
	}
}

func validateRecordLevel(level string) error {
	switch level {
	case policyRecordOrg, policyRecordProject, policyRecordPin:
		return nil
	default:
		return fmt.Errorf("unknown record %q (valid: %s, %s, %s)", level, policyRecordOrg, policyRecordProject, policyRecordPin)
	}
}

// loadConnectionPolicy reads the policy file. A missing file is a valid empty
// store. A malformed file, unknown mode/record, or an entry whose shape does
// not fit its bucket returns the error alongside safe defaults (nothing
// allowed, prompt mode): the caller must surface the error loudly, and the
// fallback lands on the TOFU prompt.
func loadConnectionPolicy() (connectionPolicy, error) {
	path, err := connectionPolicyPath()
	if err != nil {
		return connectionPolicy{Mode: policyModePrompt, Record: policyRecordProject}, err
	}
	return loadConnectionPolicyFrom(path)
}

func loadConnectionPolicyFrom(path string) (connectionPolicy, error) {
	p := connectionPolicy{Mode: policyModePrompt, Record: policyRecordProject, path: path}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("reading %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return p, fmt.Errorf("malformed %s: %w", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 ||
		doc.Content[0].Kind != yaml.MappingNode {
		// Empty (or a bare `null` document): a valid empty store. The doc is
		// not retained — the first edit builds a fresh mapping tree.
		return p, nil
	}

	var parsed struct {
		Mode   string `yaml:"mode"`
		Record string `yaml:"record"`
		Allow  struct {
			Orgs     []string `yaml:"orgs"`
			Projects []string `yaml:"projects"`
			Pins     []string `yaml:"pins"`
		} `yaml:"allow"`
	}
	if err := doc.Decode(&parsed); err != nil {
		return p, fmt.Errorf("malformed %s: %w", path, err)
	}

	mode := strings.TrimSpace(parsed.Mode)
	if mode == "" {
		mode = policyModePrompt
	} else if err := validateMode(mode); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	level := strings.TrimSpace(parsed.Record)
	if level == "" {
		level = policyRecordProject
	} else if err := validateRecordLevel(level); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}

	orgs, err := cleanBucket(parsed.Allow.Orgs, policyRecordOrg)
	if err != nil {
		return p, fmt.Errorf("%s: allow.orgs: %w", path, err)
	}
	projects, err := cleanBucket(parsed.Allow.Projects, policyRecordProject)
	if err != nil {
		return p, fmt.Errorf("%s: allow.projects: %w", path, err)
	}
	pins, err := cleanBucket(parsed.Allow.Pins, policyRecordPin)
	if err != nil {
		return p, fmt.Errorf("%s: allow.pins: %w", path, err)
	}

	p.Mode, p.Record = mode, level
	p.Orgs, p.Projects, p.Pins = orgs, projects, pins
	p.doc = &doc
	return p, nil
}

// cleanBucket trims entries and verifies each fits its bucket's shape, so a
// project pasted under orgs grants org-wide nothing rather than something
// surprising.
func cleanBucket(entries []string, level string) ([]string, error) {
	var out []string
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if err := validateEntry(trimmed, level); err != nil {
			return nil, err
		}
		out = append(out, trimmed)
	}
	return out, nil
}

func validateEntry(entry, level string) error {
	switch level {
	case policyRecordOrg:
		if strings.ContainsAny(entry, "/@") {
			return fmt.Errorf("%q is not an org name (orgs hold a bare name; projects and pins have their own sections)", entry)
		}
		return nil
	case policyRecordProject:
		if strings.Contains(entry, "@") {
			return fmt.Errorf("%q is pinned (pins have their own section)", entry)
		}
		repo, _, _, err := verify.ParseReference(entry)
		if err != nil || repo != entry {
			return fmt.Errorf("%q is not an org/project reference", entry)
		}
		return nil
	case policyRecordPin:
		_, tag, _, err := verify.ParseReference(entry)
		if err != nil {
			return fmt.Errorf("invalid pin %q: %v", entry, err)
		}
		if tag == "" {
			return fmt.Errorf("%q has no revision (unpinned projects have their own section)", entry)
		}
		return nil
	default:
		return fmt.Errorf("unknown level %q", level)
	}
}

// matches reports whether any allow entry covers the resolved source
// reference. An entry grants exactly what it says: an org covers everything
// in it, a project covers any of its revisions, and a pin covers itself (a
// pin without digest covers any digest of that revision). Strictness is the
// granularity written down; the record setting never reinterprets existing
// entries.
func (p connectionPolicy) matches(source string) bool {
	source = strings.TrimSpace(source)
	if source == "" {
		return false
	}
	for _, bucket := range [][]string{p.Orgs, p.Projects, p.Pins} {
		for _, entry := range bucket {
			if entry == source ||
				strings.HasPrefix(source, entry+"/") ||
				strings.HasPrefix(source, entry+"@") {
				return true
			}
		}
	}
	return false
}

// hasPin reports whether the exact reference is already journaled.
func (p connectionPolicy) hasPin(source string) bool {
	return containsEntry(p.Pins, source)
}

func (p connectionPolicy) hasEntry(level, value string) bool {
	switch level {
	case policyRecordOrg:
		return containsEntry(p.Orgs, value)
	case policyRecordProject:
		return containsEntry(p.Projects, value)
	case policyRecordPin:
		return containsEntry(p.Pins, value)
	}
	return false
}

func containsEntry(entries []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, entry := range entries {
		if entry == value {
			return true
		}
	}
	return false
}

// entryForLevel reduces a full source reference to the granularity that a
// prompt-yes should record: the org, the org/project, or the exact
// reference.
func entryForLevel(source, level string) (string, error) {
	source = strings.TrimSpace(source)
	repo, _, _, err := verify.ParseReference(source)
	if err != nil {
		return "", fmt.Errorf("invalid reference %q: %w", source, err)
	}
	switch level {
	case policyRecordOrg:
		org, _, ok := strings.Cut(repo, "/")
		if !ok || org == "" {
			return "", fmt.Errorf("reference %q has no org component", source)
		}
		return org, nil
	case policyRecordProject:
		return repo, nil
	case policyRecordPin:
		return source, nil
	default:
		return "", fmt.Errorf("unknown level %q", level)
	}
}

// recordTrust writes a prompt-yes: the reference at the store's configured
// record granularity and at every narrower one (an org-yes also records the
// project and the exact pin). Trust is inclusive going down, so tightening
// later starts from everything already used instead of re-prompting for it.
// Deduplicated per bucket; one atomic write for the whole cascade.
func (p *connectionPolicy) recordTrust(source string) error {
	_, err := p.recordTrustAt(source, p.Record)
	return err
}

// recordTrustAt records at an explicit granularity (a --repo assertion's own
// level) without touching the store's configured record default. It reports
// whether anything new was written.
func (p *connectionPolicy) recordTrustAt(source, fromLevel string) (bool, error) {
	_, tag, _, err := verify.ParseReference(strings.TrimSpace(source))
	if err != nil {
		return false, fmt.Errorf("invalid reference %q: %w", source, err)
	}
	levels := []string{policyRecordOrg, policyRecordProject, policyRecordPin}
	for i, level := range levels {
		if level != fromLevel {
			continue
		}
		levels = levels[i:]
		break
	}
	changed := false
	for _, level := range levels {
		if level == policyRecordPin && tag == "" {
			continue // a bare repo reference has nothing to pin
		}
		entry, err := entryForLevel(source, level)
		if err != nil {
			return false, err
		}
		if p.hasEntry(level, entry) {
			continue
		}
		if err := p.appendEntry(level, entry); err != nil {
			return false, err
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, p.save()
}

// recordPin journals the exact reference a successful connect resolved to
// and reports whether it was new. Deduplicated; callers skip it entirely for
// --dangerous connects — a bypass must never become standing trust.
func (p *connectionPolicy) recordPin(source string) (bool, error) {
	source = strings.TrimSpace(source)
	if err := validateEntry(source, policyRecordPin); err != nil {
		return false, err
	}
	if p.hasPin(source) {
		return false, nil
	}
	if err := p.appendEntry(policyRecordPin, source); err != nil {
		return false, err
	}
	return true, p.save()
}

// setDefaults updates mode and/or record granularity (empty string keeps the
// current value) and writes the store, preserving comments and the allow
// list.
func (p *connectionPolicy) setDefaults(mode, level string) error {
	if mode == "" {
		mode = p.Mode
	}
	if level == "" {
		level = p.Record
	}
	if err := validateMode(mode); err != nil {
		return err
	}
	if err := validateRecordLevel(level); err != nil {
		return err
	}
	if err := p.ensureDoc(); err != nil {
		return err
	}
	if err := setMappingScalar(p.doc, "mode", mode); err != nil {
		return fmt.Errorf("editing %s: %w", p.path, err)
	}
	if err := setMappingScalar(p.doc, "record", level); err != nil {
		return fmt.Errorf("editing %s: %w", p.path, err)
	}
	p.Mode, p.Record = mode, level
	return p.save()
}

// appendEntry places a value in the bucket for the given level, editing the
// in-memory tree only — callers persist with save, so a cascade of appends
// is one atomic write. Pins insert at their sorted position so a project's
// history groups together.
func (p *connectionPolicy) appendEntry(level, value string) error {
	value = strings.TrimSpace(value)
	if err := validateEntry(value, level); err != nil {
		return err
	}
	if err := p.ensureDoc(); err != nil {
		return err
	}
	if err := appendBucketNode(p.doc, policyRecordBuckets[level], value, level == policyRecordPin); err != nil {
		return fmt.Errorf("editing %s: %w", p.path, err)
	}
	switch level {
	case policyRecordOrg:
		p.Orgs = append(p.Orgs, value)
	case policyRecordProject:
		p.Projects = append(p.Projects, value)
	case policyRecordPin:
		p.Pins = append(p.Pins, value)
	}
	return nil
}

// ensureDoc guarantees an editable YAML tree: the loaded file's tree when
// one exists, otherwise a fresh mode/record/allow mapping built in memory
// (never read back from disk — what we built is the state).
func (p *connectionPolicy) ensureDoc() error {
	if p.path == "" {
		path, err := connectionPolicyPath()
		if err != nil {
			return err
		}
		p.path = path
	}
	if p.doc != nil {
		return nil
	}
	// An ordered struct, not a map: the fresh file should read
	// mode/record/allow top to bottom, like the documented example.
	fresh := struct {
		Mode   string `yaml:"mode"`
		Record string `yaml:"record"`
	}{Mode: p.Mode, Record: p.Record}
	data, err := yaml.Marshal(fresh)
	if err != nil {
		return fmt.Errorf("building fresh store: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("building fresh store: %w", err)
	}
	p.doc = &doc
	return nil
}

// save persists the in-memory tree with one atomic write.
func (p *connectionPolicy) save() error {
	if p.doc == nil {
		return fmt.Errorf("nothing to save")
	}
	data, err := yaml.Marshal(p.doc)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", p.path, err)
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(p.path), err)
	}
	if err := writeAtomic(p.path, data); err != nil {
		return fmt.Errorf("writing %s: %w", p.path, err)
	}
	return nil
}

// broaderThan returns the allow entries that grant more than the given
// record granularity: org entries for project, org and project entries for
// pin. These are what keep matching after a tightening until pruned.
func (p connectionPolicy) broaderThan(level string) []string {
	switch level {
	case policyRecordProject:
		return append([]string(nil), p.Orgs...)
	case policyRecordPin:
		return append(append([]string(nil), p.Orgs...), p.Projects...)
	default:
		return nil
	}
}

// pruneBroaderThan removes the allow buckets broader than the given record
// granularity and writes the store, so tightening can take full effect in
// one deliberate step. Comments outside the removed buckets survive.
func (p *connectionPolicy) pruneBroaderThan(level string) error {
	if len(p.broaderThan(level)) == 0 || p.doc == nil {
		return nil
	}
	buckets := []string{"orgs"}
	if level == policyRecordPin {
		buckets = append(buckets, "projects")
	}
	root := p.doc.Content[0]
	allow, err := mappingValue(root, "allow")
	if err != nil {
		return err
	}
	for _, bucket := range buckets {
		removeMappingKey(allow, bucket)
	}
	p.Orgs = nil
	if level == policyRecordPin {
		p.Projects = nil
	}
	return p.save()
}

func removeMappingKey(mapping *yaml.Node, key string) {
	if mapping.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

// setMappingScalar sets a top-level key to a scalar value, keeping any
// comments attached to the key, or appends the key when absent.
func setMappingScalar(doc *yaml.Node, key, value string) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("unexpected YAML document shape")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("top level is not a mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			node := root.Content[i+1]
			node.Kind, node.Tag, node.Value, node.Content = yaml.ScalarNode, "!!str", value, nil
			return nil
		}
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value},
	)
	return nil
}

// appendBucketNode places a scalar in allow.<bucket>, creating the mapping
// levels as needed. Editing the parsed tree (rather than re-marshaling a
// struct) is what preserves user comments. sorted inserts the value at its
// ordered position among existing entries (never reordering them) so journal
// pins group by project.
func appendBucketNode(doc *yaml.Node, bucket, value string, sorted bool) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("unexpected YAML document shape")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("top level is not a mapping")
	}
	allow, err := mappingValue(root, "allow")
	if err != nil {
		return err
	}
	seq, err := mappingValue(allow, bucket)
	if err != nil {
		return err
	}
	if seq.Kind != yaml.SequenceNode {
		// e.g. `pins:` with no entries parses as a null scalar.
		*seq = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Value: value}
	at := len(seq.Content)
	if sorted {
		at = sort.Search(len(seq.Content), func(i int) bool {
			return seq.Content[i].Value > value
		})
	}
	seq.Content = append(seq.Content, nil)
	copy(seq.Content[at+1:], seq.Content[at:])
	seq.Content[at] = scalar
	return nil
}

// mappingValue returns the value node for key, appending an empty mapping
// entry when the key is absent and coercing a bare `key:` (null value) into
// one.
func mappingValue(mapping *yaml.Node, key string) (*yaml.Node, error) {
	if mapping.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%q is not a mapping", key)
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			node := mapping.Content[i+1]
			if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
				*node = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			return node, nil
		}
	}
	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		value,
	)
	return value, nil
}
