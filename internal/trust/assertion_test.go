package trust

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssertionRecordPreservesCallerGranularity(t *testing.T) {
	source := "acme/api@r12@" + testDigestA
	for _, tc := range []struct {
		assertion, reference, level, entry string
	}{
		{"acme", source, RecordOrg, "acme"},
		{"acme/api", source, RecordProject, "acme/api"},
		{source, source, RecordPin, source},
		{"acme/api@" + testDigestA, "acme/api@" + testDigestA, RecordPin, "acme/api@" + testDigestA},
		{"acme/api@r12", "acme/api@r12", RecordPin, "acme/api@r12"},
	} {
		reference, level, err := AssertionRecord(tc.assertion, source)
		require.NoError(t, err)
		require.Equal(t, tc.reference, reference)
		require.Equal(t, tc.level, level)
		path := filepath.Join(t.TempDir(), "trust.json")
		policy, err := Load(path)
		require.NoError(t, err)
		changed, err := policy.RecordTrustAt(reference, level)
		require.NoError(t, err)
		require.True(t, changed)
		policy, err = Load(path)
		require.NoError(t, err)
		require.True(t, policy.Matches(source))
		require.True(t, policy.hasEntry(level, tc.entry))
		if level != RecordOrg {
			require.Empty(t, policy.Allow.Orgs)
		}
		if level == RecordPin {
			require.Empty(t, policy.Allow.Projects)
		}
		require.Equal(t, RecordProject, policy.Record)
	}
	for _, assertion := range []string{"", "widgets", "acme/other", "acme/api@r13@" + testDigestB, "acmecorp", "acme/api@" + testDigestB, "acme/api@r13@" + testDigestA} {
		_, _, err := AssertionRecord(assertion, source)
		require.Error(t, err)
	}
}
