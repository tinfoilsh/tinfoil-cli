package trust

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func projectPin(reference string) verify.Pin { return verify.Pin{Project: reference} }

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
		reference, level, err := AssertionRecord(projectPin(tc.assertion), projectPin(source))
		require.NoError(t, err)
		require.Equal(t, projectPin(tc.reference), reference)
		require.Equal(t, tc.level, level)
		path := filepath.Join(t.TempDir(), "trust.json")
		policy, err := Load(path)
		require.NoError(t, err)
		changed, err := policy.RecordTrustAt(reference, level)
		require.NoError(t, err)
		require.True(t, changed)
		policy, err = Load(path)
		require.NoError(t, err)
		require.True(t, policy.Matches(projectPin(source)))
		require.True(t, policy.Allow.hasEntry(level, tc.entry))
		if level != RecordOrg {
			require.Empty(t, policy.Allow.Orgs)
		}
		if level == RecordPin {
			require.Empty(t, policy.Allow.Projects)
		}
		require.Equal(t, RecordProject, policy.Record)
	}
	for _, assertion := range []string{"", "widgets", "acme/other", "acme/api@r13@" + testDigestB, "acmecorp", "acme/api@" + testDigestB, "acme/api@r13@" + testDigestA} {
		_, _, err := AssertionRecord(projectPin(assertion), projectPin(source))
		require.Error(t, err)
	}
}

func TestAssertionRecordKeepsNamespacesApart(t *testing.T) {
	release := verify.Pin{Repo: "acme/api@v1"}
	config := projectPin("acme/api@r12@" + testDigestA)

	_, _, err := AssertionRecord(verify.Pin{Repo: "acme/api"}, config)
	require.ErrorContains(t, err, "is asserted with --project, not --repo")
	_, _, err = AssertionRecord(projectPin("acme/api"), release)
	require.ErrorContains(t, err, "is asserted with --repo, not --project")

	record, level, err := AssertionRecord(verify.Pin{Repo: "acme/api", Project: "other/app"}, release)
	require.NoError(t, err)
	require.Equal(t, release, record)
	require.Equal(t, RecordProject, level)

	path := filepath.Join(t.TempDir(), "trust.json")
	policy, err := Load(path)
	require.NoError(t, err)
	_, err = policy.RecordTrustAt(record, level)
	require.NoError(t, err)
	policy, err = Load(path)
	require.NoError(t, err)
	require.Equal(t, AllowList{Projects: []string{"acme/api"}, Pins: []string{"acme/api@v1"}}, policy.GitHub)
	require.Empty(t, policy.Allow)
	require.True(t, policy.Matches(verify.Pin{Repo: "acme/api@v2"}))
	require.True(t, policy.HasPin(release))
	require.False(t, policy.Matches(projectPin("acme/api@v2")), "a GitHub repository entry must not match a registry project")
	require.False(t, policy.HasPin(projectPin("acme/api@v1")))
	require.False(t, policy.Matches(verify.Pin{Repo: "acme/api@v1", Project: "acme/api@v1"}))

	_, err = policy.RecordTrustAt(config, RecordOrg)
	require.NoError(t, err)
	policy, err = Load(path)
	require.NoError(t, err)
	require.True(t, policy.Matches(projectPin("acme/other@r1")))
	require.False(t, policy.Matches(verify.Pin{Repo: "acme/other@r1"}), "a registry org entry must not match a GitHub owner")
	require.Equal(t, []string{"acme", "acme/api", "acme/api"}, policy.BroaderThan(RecordPin))
	require.NoError(t, policy.PruneBroaderThan(RecordPin))
	require.Empty(t, policy.GitHub.Projects)
	require.Empty(t, policy.Allow.Orgs)
}
