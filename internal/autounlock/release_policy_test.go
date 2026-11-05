package autounlock

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	policyreference "github.com/tinfoilsh/tinfoil-cli/testdata/keyserverpolicy"
)

func storageTestV2WorkloadName() string {
	digest := sha256.Sum256([]byte(`{"repo":"owner/repo","tag":"v2.0.0","domain":"app.example.com"}`))
	return fmt.Sprintf("volume-%s-%x", testVolumeID, digest)
}

func storageTestConflictingV2Policy(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	conflict := fmt.Sprintf("  %s:\n    repo: another/repo\n    tag: v9.0.0\n    domain: other.example.com\n    secrets:\n      OTHER: {path: another/key, field: value}\n", storageTestV2WorkloadName())
	return append(raw, []byte(conflict)...)
}

func TestStorageReleasePolicyPreservesCommentsAndOtherMappings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	raw = append([]byte("# preserve prior approval\nfuture-setting: keep\n"), raw...)
	raw = bytes.Replace(raw, []byte("    secrets:\n"), []byte("    secrets: # preserve old mappings\n      APP_TOKEN: {path: app/token, field: value}\n"), 1)
	original := bytes.Clone(raw)
	r := testStorageReceipt()
	r.Tag = "v2.0.0"
	out, err := prepareVolumePolicy(raw, r, "volumes/"+r.VolumeID+"/key")
	require.NoError(t, err)
	require.Equal(t, original, raw)
	for _, text := range []string{"# preserve prior approval", "future-setting: keep", "# preserve old mappings", "APP_TOKEN: {path: app/token, field: value}", "tag: v1.0.0"} {
		require.Contains(t, string(out), text)
	}
	path := filepath.Join(t.TempDir(), "policy.yml")
	require.NoError(t, os.WriteFile(path, out, storageFileMode))
	loaded, err := policyreference.LoadPolicy(path)
	require.NoError(t, err)
	_, old := loaded.Match(r.Profile.Scope.Repo, "v1.0.0")
	require.NotNil(t, old)
	_, err = old.Authorize("old", []string{r.KeySecret, "APP_TOKEN"})
	require.NoError(t, err)
	_, current := loaded.Match(r.Profile.Scope.Repo, r.Tag)
	require.NotNil(t, current)
	require.Equal(t, old.Secrets[r.KeySecret], current.Secrets[r.KeySecret])
	require.NotContains(t, current.Secrets, "APP_TOKEN")
	r.Domain = "other.example.com"
	_, err = prepareVolumePolicy(out, r, "volumes/"+r.VolumeID+"/key")
	require.ErrorContains(t, err, "only one domain per repo/tag")
}

func TestStorageReleasePolicyRejectsConflictingDerivedName(t *testing.T) {
	raw := storageTestConflictingV2Policy(t)
	original := bytes.Clone(raw)
	r := testStorageReceipt()
	r.Tag = "v2.0.0"
	out, err := prepareVolumePolicy(raw, r, "volumes/"+r.VolumeID+"/key")
	require.ErrorContains(t, err, "release-specific workload name")
	require.Nil(t, out)
	require.Equal(t, original, raw)
}

func TestStorageReleasePolicyReusesOperatorNamedApproval(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	raw = append(raw, []byte("  reviewed-v2:\n    repo: owner/repo\n    tag: v2.0.0\n    domain: app.example.com\n    secrets:\n      APP_TOKEN: {path: app/token, field: value}\n")...)
	r := testStorageReceipt()
	r.Tag = "v2.0.0"
	out, err := prepareVolumePolicy(raw, r, "volumes/"+r.VolumeID+"/key")
	require.NoError(t, err)
	require.NotContains(t, string(out), storageTestV2WorkloadName())
	path := filepath.Join(t.TempDir(), "policy.yml")
	require.NoError(t, os.WriteFile(path, out, storageFileMode))
	loaded, err := policyreference.LoadPolicy(path)
	require.NoError(t, err)
	require.Len(t, loaded.Workloads, 2)
	name, workload := loaded.Match(r.Profile.Scope.Repo, r.Tag)
	require.Equal(t, "reviewed-v2", name)
	_, err = workload.Authorize(name, []string{r.KeySecret, "APP_TOKEN"})
	require.NoError(t, err)
	again, err := prepareVolumePolicy(out, r, "volumes/"+r.VolumeID+"/key")
	require.NoError(t, err)
	require.Equal(t, out, again)
	_, err = prepareVolumePolicy(out, r, "replacement/key")
	require.ErrorContains(t, err, "refusing to overwrite")
}

func TestStorageReleasePolicyNamesIncludeEveryPin(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "volume-policy-v1.yml"))
	require.NoError(t, err)
	names := map[string]bool{}
	for _, variant := range []string{"baseline", "repo", "tag", "domain"} {
		r := testStorageReceipt()
		r.Tag = "v2.0.0"
		switch variant {
		case "repo":
			r.Profile.Scope.Repo = "another/repo"
		case "tag":
			r.Tag = "v3.0.0"
		case "domain":
			r.Domain = "other.example.com"
		}
		out, err := prepareVolumePolicy(raw, r, "volumes/"+r.VolumeID+"/key")
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "policy.yml")
		require.NoError(t, os.WriteFile(path, out, storageFileMode))
		loaded, err := policyreference.LoadPolicy(path)
		require.NoError(t, err)
		name, _ := loaded.Match(r.Profile.Scope.Repo, r.Tag)
		require.True(t, strings.HasPrefix(name, "volume-"+r.VolumeID+"-"))
		require.False(t, names[name], "every changed pin must affect the derived name")
		names[name] = true
		if variant == "baseline" {
			require.Equal(t, storageTestV2WorkloadName(), name)
		}
	}
}
