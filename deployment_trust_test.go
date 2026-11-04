package main

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func deploymentFixture(t *testing.T) deploymentRecord {
	t.Helper()
	gateEnv(t, `{"allow":{"projects":["acme/api"]}}`)
	return deploymentRecord{Host: "api.example.com:443", Scope: configendorsement.ScopePrefix + strings.Repeat("f", 32), Project: "acme/api", Digest: strings.TrimPrefix(testDigestA, "sha256:")}
}

func TestDeploymentFollowDoesNotBroadenPolicy(t *testing.T) {
	record := deploymentFixture(t)
	policyPath, err := connectionPolicyPath()
	require.NoError(t, err)
	before, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	require.NoError(t, rememberDeployment(record, false, updatesFollow, strings.NewReader(""), &bytes.Buffer{}, false))
	record.Digest = strings.TrimPrefix(testDigestB, "sha256:")
	require.NoError(t, rememberDeployment(record, false, updatesFollow, strings.NewReader(""), &bytes.Buffer{}, false))
	path, err := knownDeploymentsPath()
	require.NoError(t, err)
	records, err := readDeployments(path)
	require.NoError(t, err)
	require.Equal(t, map[string]deploymentRecord{record.Host: record}, records)
	after, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, storageFileMode, info.Mode().Perm())
}

func TestDeploymentAskRequiresApprovalForChangesAndRollback(t *testing.T) {
	record := deploymentFixture(t)
	var out bytes.Buffer
	require.Error(t, rememberDeployment(record, false, updatesAsk, strings.NewReader(""), &out, false))
	require.NoError(t, rememberDeployment(record, false, updatesAsk, strings.NewReader("yes\n"), &out, true))
	updated := record
	updated.Digest = strings.TrimPrefix(testDigestB, "sha256:")
	require.Error(t, rememberDeployment(updated, false, updatesAsk, strings.NewReader("\n"), &out, true))
	require.NoError(t, rememberDeployment(updated, false, updatesAsk, strings.NewReader("yes\n"), &out, true))
	require.Error(t, rememberDeployment(record, false, updatesAsk, strings.NewReader("no\n"), &out, true))
	path, err := knownDeploymentsPath()
	require.NoError(t, err)
	records, err := readDeployments(path)
	require.NoError(t, err)
	require.Equal(t, updated, records[record.Host])
}

func TestDeploymentIdentityChangesNeedExplicitForgetting(t *testing.T) {
	record := deploymentFixture(t)
	require.NoError(t, rememberDeployment(record, false, updatesFollow, strings.NewReader(""), &bytes.Buffer{}, false))
	for _, change := range []string{"scope", "project"} {
		other := record
		if change == "scope" {
			other.Scope = configendorsement.PublicScope
		} else {
			other.Project = "acme/other"
		}
		require.ErrorContains(t, rememberDeployment(other, true, updatesFollow, strings.NewReader("yes\n"), &bytes.Buffer{}, true), "identity changed")
	}
	require.NoError(t, executeLifecycleCLI(t, "trust", "forget", record.Host))
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []string{"acme/api"}, policy.Allow.Projects)
	path, err := knownDeploymentsPath()
	require.NoError(t, err)
	records, err := readDeployments(path)
	require.NoError(t, err)
	require.Empty(t, records)
}

func TestDeploymentPinnedRequiresAnExplicitDigest(t *testing.T) {
	record := deploymentFixture(t)
	require.Error(t, rememberDeployment(record, false, updatesPinned, strings.NewReader(""), &bytes.Buffer{}, false))
	require.NoError(t, rememberDeployment(record, true, updatesPinned, strings.NewReader(""), &bytes.Buffer{}, false))
	require.NoError(t, rememberDeployment(record, false, updatesPinned, strings.NewReader(""), &bytes.Buffer{}, false))
	record.Digest = strings.TrimPrefix(testDigestB, "sha256:")
	require.Error(t, rememberDeployment(record, false, updatesPinned, strings.NewReader(""), &bytes.Buffer{}, false))
	require.NoError(t, rememberDeployment(record, true, updatesPinned, strings.NewReader(""), &bytes.Buffer{}, false))
}

func TestDeploymentRecordsRejectCorruptionWithoutOverwriting(t *testing.T) {
	record := deploymentFixture(t)
	valid, err := json.Marshal(record)
	require.NoError(t, err)
	for _, content := range []string{
		`{broken`,
		strings.Replace(string(valid), `"host":`, `"unexpected":true,"host":`, 1),
		strings.Replace(string(valid), record.Scope, record.Scope+"/", 1),
		strings.Replace(string(valid), record.Digest, "bad", 1),
		string(valid) + "\n" + string(valid) + "\n",
	} {
		path := filepath.Join(t.TempDir(), knownDeploymentsFileName)
		t.Setenv(envKnownDeployments, path)
		require.NoError(t, os.WriteFile(path, []byte(content), storageFileMode))
		require.Error(t, rememberDeployment(record, false, updatesFollow, strings.NewReader(""), &bytes.Buffer{}, false))
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, content, string(after))
	}
}

func TestDeploymentConcurrentUpdatesPreserveBothEndpoints(t *testing.T) {
	record := deploymentFixture(t)
	errors := make(chan error, 2)
	for _, host := range []string{"one.example.com:443", "two.example.com:443"} {
		other := record
		other.Host = host
		go func() {
			errors <- rememberDeployment(other, false, updatesFollow, strings.NewReader(""), &bytes.Buffer{}, false)
		}()
	}
	for range 2 {
		require.NoError(t, <-errors)
	}
	path, err := knownDeploymentsPath()
	require.NoError(t, err)
	records, err := readDeployments(path)
	require.NoError(t, err)
	require.Len(t, records, 2)
}

func TestDeploymentUpdatePolicyDefaultsAndValidation(t *testing.T) {
	deploymentFixture(t)
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, updatesFollow, policy.Updates)
	require.NoError(t, executeLifecycleCLI(t, "trust", "set", "--updates", "ask"))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, updatesAsk, policy.Updates)
	require.Equal(t, []string{"acme/api"}, policy.Allow.Projects)
	require.Error(t, executeLifecycleCLI(t, "trust", "set", "--updates", "unknown"))
}
