package trust

import (
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// AssertionRecord checks a resolved config against the caller's assertion in
// the same namespace and returns what to record for it.
func AssertionRecord(asserted, resolved verify.Pin) (record verify.Pin, level string, err error) {
	resolvedSource, err := Reference(resolved)
	if err != nil {
		return verify.Pin{}, "", err
	}
	flag := Flag(resolved)
	assertion := strings.TrimSpace(asserted.Project)
	if resolved.Repo != "" {
		assertion = strings.TrimSpace(asserted.Repo)
	}
	if assertion == "" {
		if asserted == (verify.Pin{}) {
			return verify.Pin{}, "", fmt.Errorf("empty reference")
		}
		return verify.Pin{}, "", fmt.Errorf("resolved config %s is asserted with %s, not %s", resolvedSource, flag, Flag(asserted))
	}
	if !referenceMatches(assertion, resolvedSource) {
		return verify.Pin{}, "", fmt.Errorf("resolved config %s does not match %s %s", resolvedSource, flag, assertion)
	}
	level, err = referenceGranularity(assertion)
	if err != nil {
		return verify.Pin{}, "", fmt.Errorf("%s: %w", flag, err)
	}
	if level == RecordPin {
		return withReference(resolved, assertion), level, nil
	}
	return withReference(resolved, resolvedSource), level, nil
}

// referenceGranularity classifies a caller-stated reference: a bare name is
// an org, owner/name is a project, anything pinned is a pin.
func referenceGranularity(ref string) (string, error) {
	if !strings.Contains(ref, "/") {
		if err := validateEntry(ref, RecordOrg); err != nil {
			return "", err
		}
		return RecordOrg, nil
	}
	_, tag, digest, err := verify.ParseReference(ref)
	if err != nil {
		return "", err
	}
	if tag == "" && digest == "" {
		return RecordProject, nil
	}
	return RecordPin, nil
}
