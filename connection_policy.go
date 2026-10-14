package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// The known-configs store holds the caller's side of connection verification:
// which registry references this user has chosen to trust, at the granularity
// they wrote them down — whole orgs, projects (any revision), or exact pins.
//
// The pins bucket doubles as a journal: every successful connect records the
// exact reference it resolved to (deduplicated, never on --dangerous). A pin
// not yet present is announced as new.
const (
	envKnownConfigs                = "TINFOIL_KNOWN_CONFIGS"
	connectionPolicyFileName       = "known-configs.json"
	legacyConnectionPolicyFileName = "known-configs.yml"

	// mode: what happens when a descriptor matches no allow entry.
	policyModePrompt = "prompt" // ask yes/no; yes records at the configured granularity
	policyModeFrozen = "frozen" // fail closed; the file changes only by hand

	// record granularity: what a prompt-yes writes.
	policyRecordOrg     = "org"     // everything in the org
	policyRecordProject = "project" // any revision of the project
	policyRecordPin     = "pin"     // the exact reference
)

type connectionPolicy struct {
	Mode   string `json:"mode"`
	Record string `json:"record"`
	Allow  struct {
		Orgs     []string `json:"orgs,omitempty"`
		Projects []string `json:"projects,omitempty"`
		Pins     []string `json:"pins,omitempty"`
	} `json:"allow"`

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
	path := filepath.Join(home, ".tinfoil", connectionPolicyFileName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		legacy := filepath.Join(home, ".tinfoil", legacyConnectionPolicyFileName)
		if _, err := os.Stat(legacy); err == nil {
			return "", fmt.Errorf("convert %s to JSON at %s before connecting", legacy, path)
		}
	}
	return path, nil
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
// store. An invalid store must be repaired before connecting.
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

	if err := json.Unmarshal(data, &p, json.RejectUnknownMembers(true)); err != nil {
		return p, fmt.Errorf("malformed %s: %w", path, err)
	}
	if jsontext.Value(data).Kind() != jsontext.KindBeginObject {
		return p, fmt.Errorf("%s: expected a JSON object", path)
	}

	p.Mode = strings.TrimSpace(p.Mode)
	if err := validateMode(p.Mode); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	p.Record = strings.TrimSpace(p.Record)
	if err := validateRecordLevel(p.Record); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}

	p.Allow.Orgs, err = cleanBucket(p.Allow.Orgs, policyRecordOrg)
	if err != nil {
		return p, fmt.Errorf("%s: allow.orgs: %w", path, err)
	}
	p.Allow.Projects, err = cleanBucket(p.Allow.Projects, policyRecordProject)
	if err != nil {
		return p, fmt.Errorf("%s: allow.projects: %w", path, err)
	}
	p.Allow.Pins, err = cleanBucket(p.Allow.Pins, policyRecordPin)
	if err != nil {
		return p, fmt.Errorf("%s: allow.pins: %w", path, err)
	}

	return p, nil
}

// cleanBucket trims entries and verifies each fits its bucket's shape, so a
// project pasted under orgs grants org-wide nothing rather than something
// surprising.
func cleanBucket(entries []string, level string) ([]string, error) {
	for i, entry := range entries {
		entries[i] = strings.TrimSpace(entry)
		if err := validateEntry(entries[i], level); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

func validateEntry(entry, level string) error {
	if entry == "" {
		return fmt.Errorf("empty %s entry", level)
	}
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
		_, tag, digest, err := verify.ParseReference(entry)
		if err != nil {
			return fmt.Errorf("invalid pin %q: %v", entry, err)
		}
		if tag == "" && digest == "" {
			return fmt.Errorf("%q has no revision or digest (unpinned projects have their own section)", entry)
		}
		return nil
	default:
		return fmt.Errorf("unknown level %q", level)
	}
}

// matches reports whether any allow entry covers the resolved source
// reference. An entry grants exactly what it says: an org covers everything
// in it, a project covers any of its revisions, and a pin requires every
// specified revision and digest to match. Strictness is the
// granularity written down; the record setting never reinterprets existing
// entries.
func (p connectionPolicy) matches(source string) bool {
	source = strings.TrimSpace(source)
	for _, bucket := range [][]string{p.Allow.Orgs, p.Allow.Projects, p.Allow.Pins} {
		for _, entry := range bucket {
			if referenceMatches(entry, source) {
				return true
			}
		}
	}
	return false
}

func referenceMatches(expected, source string) bool {
	repo, tag, digest, err := verify.ParseReference(source)
	if err != nil {
		return false
	}
	if !strings.Contains(expected, "/") {
		org, _, _ := strings.Cut(repo, "/")
		return org == expected
	}
	expectedRepo, expectedTag, expectedDigest, err := verify.ParseReference(expected)
	return err == nil && repo == expectedRepo &&
		(expectedTag == "" || tag == expectedTag) &&
		(expectedDigest == "" || digest == expectedDigest)
}

// hasPin reports whether the exact reference is already journaled.
func (p connectionPolicy) hasPin(source string) bool {
	return containsEntry(p.Allow.Pins, source)
}

func (p connectionPolicy) hasEntry(level, value string) bool {
	switch level {
	case policyRecordOrg:
		return containsEntry(p.Allow.Orgs, value)
	case policyRecordProject:
		return containsEntry(p.Allow.Projects, value)
	case policyRecordPin:
		return containsEntry(p.Allow.Pins, value)
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
	_, tag, digest, err := verify.ParseReference(strings.TrimSpace(source))
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
		if level == policyRecordPin && tag == "" && digest == "" {
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
// current value) and writes the store, preserving the allow list.
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
	p.Mode, p.Record = mode, level
	return p.save()
}

// appendEntry places a value in the bucket for the given level, editing the
// in-memory store only — callers persist with save, so a cascade of appends
// is one atomic write. Pins insert at their sorted position so a project's
// history groups together.
func (p *connectionPolicy) appendEntry(level, value string) error {
	value = strings.TrimSpace(value)
	if err := validateEntry(value, level); err != nil {
		return err
	}
	switch level {
	case policyRecordOrg:
		p.Allow.Orgs = append(p.Allow.Orgs, value)
	case policyRecordProject:
		p.Allow.Projects = append(p.Allow.Projects, value)
	case policyRecordPin:
		p.Allow.Pins = append(p.Allow.Pins, value)
		sort.Strings(p.Allow.Pins)
	}
	return nil
}

// save persists the in-memory store with one atomic write.
func (p *connectionPolicy) save() error {
	if p.path == "" {
		path, err := connectionPolicyPath()
		if err != nil {
			return err
		}
		p.path = path
	}
	data, err := json.Marshal(p, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("encoding %s: %w", p.path, err)
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(p.path), err)
	}
	if err := writeAtomic(p.path, append(data, '\n')); err != nil {
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
		return append([]string(nil), p.Allow.Orgs...)
	case policyRecordPin:
		return append(append([]string(nil), p.Allow.Orgs...), p.Allow.Projects...)
	default:
		return nil
	}
}

// pruneBroaderThan removes the allow buckets broader than the given record
// granularity and writes the store, so tightening can take full effect in
// one deliberate step.
func (p *connectionPolicy) pruneBroaderThan(level string) error {
	if len(p.broaderThan(level)) == 0 {
		return nil
	}
	p.Allow.Orgs = nil
	if level == policyRecordPin {
		p.Allow.Projects = nil
	}
	return p.save()
}
