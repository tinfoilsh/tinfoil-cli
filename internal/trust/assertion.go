package trust

import (
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

func AssertionRecord(assertion, resolvedSource string) (reference, level string, err error) {
	assertion = strings.TrimSpace(assertion)
	resolvedSource = strings.TrimSpace(resolvedSource)
	if assertion == "" || resolvedSource == "" {
		return "", "", fmt.Errorf("empty reference")
	}
	if !referenceMatches(assertion, resolvedSource) {
		return "", "", fmt.Errorf("resolved config %s does not match --repo %s", resolvedSource, assertion)
	}
	level, err = referenceGranularity(assertion)
	if err != nil {
		return "", "", fmt.Errorf("--repo: %w", err)
	}
	if level == RecordPin {
		return assertion, level, nil
	}
	return resolvedSource, level, nil
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
