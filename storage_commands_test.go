package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type storageCPFixture struct {
	server          *httptest.Server
	mu              sync.Mutex
	requests        []string
	allocations     int
	allocationFails bool
}

func newStorageCPFixture(t *testing.T) *storageCPFixture {
	t.Helper()
	f := &storageCPFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) || !assert.NotContains(t, string(body), storageTestEncoded) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			org := "org_test"
			if r.Header.Get("Authorization") == "Bearer admin_other" {
				org = "org_other"
			}
			_, _ = io.WriteString(w, `{"context_type":"organization","organization":{"id":"`+org+`"},"user_id":"user_test"}`)
		case "GET /api/github/repos/owner/repo/config":
			_, _ = io.WriteString(w, `{"success":true,"exists":false,"default_branch":"main"}`)
		case "GET /api/containers/projects":
			_, _ = io.WriteString(w, `[{"id":"project_test","repo":"Owner/Repo"}]`)
		case "GET /api/containers/hosts":
			_, _ = io.WriteString(w, `[{"id":"h1","name":"inf13"}]`)
		case "POST /api/volumes":
			f.allocations++
			var allocation map[string]any
			if !assert.NoError(t, json.Unmarshal(body, &allocation)) || !assert.Len(t, allocation, 3) || !assert.Equal(t, "h1", allocation["host_id"]) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.allocationFails {
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			}
			_, _ = io.WriteString(w, testVolumeRow(false))
		case "GET /api/volumes":
			_, _ = io.WriteString(w, testVolumeList(false))
		default:
			t.Errorf("unexpected controlplane mutation/request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(f.server.Close)
	configureVolumeTest(t, f.server.URL)
	return f
}

func executeStorageCLI(t *testing.T, factory storageStoreFactory, args ...string) (string, error) {
	t.Helper()
	oldFactory := volumeStorageFactory
	volumeStorageFactory = factory
	defer func() { volumeStorageFactory = oldFactory }()
	type savedFlag struct {
		flag    *pflag.Flag
		value   string
		changed bool
	}
	var saved []savedFlag
	var save func(*cobra.Command)
	seen := map[*pflag.Flag]bool{}
	save = func(cmd *cobra.Command) {
		for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
			flags.VisitAll(func(f *pflag.Flag) {
				if !seen[f] {
					saved = append(saved, savedFlag{f, f.Value.String(), f.Changed})
					seen[f] = true
				}
			})
		}
		for _, sub := range cmd.Commands() {
			save(sub)
		}
	}
	save(rootCmd)
	defer func() {
		for _, f := range saved {
			if f.flag.Value.Type() == "stringArray" || f.flag.Value.Type() == "stringSlice" {
				continue
			}
			require.NoError(t, f.flag.Value.Set(f.value))
			f.flag.Changed = f.changed
		}
	}()
	var output bytes.Buffer
	oldOut, oldErr, oldIn := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr(), rootCmd.InOrStdin()
	rootCmd.SetOut(&output)
	rootCmd.SetErr(&output)
	rootCmd.SetIn(strings.NewReader(""))
	defer func() { rootCmd.SetOut(oldOut); rootCmd.SetErr(oldErr); rootCmd.SetIn(oldIn); rootCmd.SetArgs(nil) }()
	rootCmd.SetArgs(args)
	stdout, err := captureTestStdout(func() error { return rootCmd.Execute() })
	all := output.String() + string(stdout)
	require.NotContains(t, all, storageTestEncoded)
	if err != nil {
		require.NotContains(t, err.Error(), storageTestEncoded)
	}
	return all, err
}

func fakeStorageFactory(fake *fakeStorageAWS, random io.Reader) storageStoreFactory {
	return func(context.Context, storageProfile) (*volumeKeyStore, error) {
		return &volumeKeyStore{client: fake, random: random}, nil
	}
}

func forbiddenStorageFactory(t *testing.T) storageStoreFactory {
	return func(context.Context, storageProfile) (*volumeKeyStore, error) {
		t.Fatal("unexpected AWS credential/client loading")
		return nil, errors.New("forbidden")
	}
}

func configureStorageCLI(t *testing.T) {
	t.Helper()
	_, err := executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "Owner/Repo", "--keyserver-url", "https://keys.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer", "--domain", "app.example.com")
	require.NoError(t, err)
}

func storageCLIArtifactFlags(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "input.yml")
	require.NoError(t, os.WriteFile(input, []byte(storageTestConfig), storageFileMode))
	return []string{"--project", "owner/repo", "--mount", "data", "--tag", "v1.2.3", "--config-file", input, "--config-out", filepath.Join(dir, "config.yml"), "--policy-out", filepath.Join(dir, "policy.yml")}
}

func TestStorageFullCommandFlowAndNoKeyCustody(t *testing.T) {
	f := newStorageCPFixture(t)
	configureStorageCLI(t)
	fake := &fakeStorageAWS{}
	fake.beforeCreate = func(in *secretsmanager.CreateSecretInput) {
		scope := testStorageProfile().Scope
		scope.ControlplaneURL = f.server.URL
		r, err := loadStorageReceipt(scope, testVolumeID)
		require.NoError(t, err)
		require.Equal(t, storagePhaseAttempted, r.Phase)
	}
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--host", "inf13", "--auto-unlock"}, flags...)
	out, err := executeStorageCLI(t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.NoError(t, err)
	require.Contains(t, out, "CONFIGURED_LOCAL")
	require.Contains(t, out, storageUnobserved)
	require.Contains(t, out, "repo config pr owner/repo")
	require.Equal(t, 1, fake.creates)
	f.mu.Lock()
	require.Equal(t, 1, f.allocations)
	f.mu.Unlock()
	for _, path := range []string{flags[7], flags[9], flags[11]} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotContains(t, string(data), storageTestEncoded)
	}
	dir, err := storageDirectory()
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(data), storageTestEncoded)
		info, err := entry.Info()
		require.NoError(t, err)
		require.EqualValues(t, storageFileMode, info.Mode().Perm())
	}
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.EqualValues(t, storageDirMode, info.Mode().Perm())
	out, err = executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "auto-unlock", "status", testVolumeID, "--project", "owner/repo")
	require.NoError(t, err)
	require.Contains(t, out, storageUnobserved)
	readOnly := &rejectingRandom{}
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.arn}, flags...)
	out, err = executeStorageCLI(t, fakeStorageFactory(fake, readOnly), args...)
	require.NoError(t, err)
	require.Contains(t, out, storageUnobserved)
	require.Zero(t, readOnly.calls)
	require.Equal(t, 1, fake.creates)
	require.NoError(t, os.WriteFile(flags[9], []byte("changed measured configuration\n"), storageFileMode))
	out, err = executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "auto-unlock", "status", testVolumeID, "--project", "owner/repo", "--output", "json")
	require.NoError(t, err)
	require.Contains(t, out, `"configuration":"STALE"`)
	require.Contains(t, out, `"unlock":"not_observed"`)
}

func TestStoragePartialFailureRetainsVolumeAndRecoversReadOnly(t *testing.T) {
	f := newStorageCPFixture(t)
	configureStorageCLI(t)
	flags := storageCLIArtifactFlags(t)
	fake := &fakeStorageAWS{createErr: errors.New(storageTestEncoded), persistOnError: true, getErr: errors.New(storageTestEncoded)}
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, bytes.NewReader(storageTestKey)), args...)
	require.ErrorContains(t, err, "volume "+testVolumeID+" retained")
	require.ErrorContains(t, err, storagePhaseAttempted)
	require.ErrorContains(t, err, "--existing-secret customer/volumes/"+testVolumeID+"/key")
	require.Equal(t, 1, fake.creates)
	fake.getErr = nil
	reject := &rejectingRandom{}
	args = append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.name}, flags...)
	_, err = executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.NoError(t, err)
	require.Zero(t, reject.calls)
	require.Equal(t, 1, fake.creates)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 1, f.allocations)
	for _, request := range f.requests {
		require.NotContains(t, request, "DELETE")
		require.NotContains(t, request, "deploy")
	}
}

func TestStorageExistingDiskNeverGeneratesWithoutReceipt(t *testing.T) {
	newStorageCPFixture(t)
	configureStorageCLI(t)
	flags := storageCLIArtifactFlags(t)
	r := testStorageReceipt()
	fake := &fakeStorageAWS{secret: testStoredSecret(r)}
	fake.secret.tags = nil
	reject := &rejectingRandom{}
	args := append([]string{"volume", "auto-unlock", "configure", testVolumeID, "--existing-secret", fake.secret.arn}, flags...)
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, reject), args...)
	require.NoError(t, err)
	require.Zero(t, fake.creates)
	require.Zero(t, reject.calls)
}

func TestStorageProfileIsolationAndAuthPersistence(t *testing.T) {
	f := newStorageCPFixture(t)
	config, err := configPath()
	require.NoError(t, err)
	credentials := []byte(`{"api_key":"admin_saved","controlplane_url":"https://api.example.com","unrelated":{"keep":true}}`)
	require.NoError(t, os.WriteFile(config, credentials, storageFileMode))
	configureStorageCLI(t)
	actual, err := os.ReadFile(config)
	require.NoError(t, err)
	require.Equal(t, credentials, actual)
	scope := testStorageProfile().Scope
	scope.ControlplaneURL = f.server.URL
	p, err := loadStorageProfile(scope)
	require.NoError(t, err)
	_, _, err = deleteConfig()
	require.NoError(t, err)
	_, err = saveConfig(cliConfig{ControlplaneURL: f.server.URL, APIKey: "admin_saved"})
	require.NoError(t, err)
	loaded, err := loadStorageProfile(scope)
	require.NoError(t, err)
	require.Equal(t, p, loaded)
	for _, other := range []storageScope{
		{ControlplaneURL: scope.ControlplaneURL, OrgID: "org_other", Repo: scope.Repo},
		{ControlplaneURL: "https://other.example.com", OrgID: scope.OrgID, Repo: scope.Repo},
		{ControlplaneURL: scope.ControlplaneURL, OrgID: scope.OrgID, Repo: "owner/other"},
	} {
		_, err := loadStorageProfile(other)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	t.Setenv(envAdminKey, "admin_other")
	out, err := executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "auto-unlock", "status", testVolumeID, "--project", "Owner/Repo")
	require.NoError(t, err)
	require.Contains(t, out, "UNKNOWN")
	require.Contains(t, out, "not evidence")
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, storageCLIArtifactFlags(t)...)
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), args...)
	require.ErrorContains(t, err, "no local storage profile")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Zero(t, f.allocations)
}

func TestStorageCommandPreflightAndNormalCreate(t *testing.T) {
	f := newStorageCPFixture(t)
	_, err := executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "owner/repo")
	require.ErrorContains(t, err, "noninteractive")
	configureStorageCLI(t)
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "project_test", "--keyserver-url", "https://different.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer")
	require.ErrorContains(t, err, "refusing implicit reconfiguration")
	profileJSON, err := executeStorageCLI(t, forbiddenStorageFactory(t), "project", "storage", "configure", "project_test", "--keyserver-url", "https://keys.example.com", "--aws-region", "us-east-2", "--aws-prefix", "customer", "--domain", "app.example.com", "--output", "json")
	require.NoError(t, err)
	var profileOutput map[string]any
	require.NoError(t, json.Unmarshal([]byte(profileJSON), &profileOutput))
	require.Equal(t, "not_applied", profileOutput["policy"])
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "auto-unlock", "configure", testVolumeID)
	require.ErrorContains(t, err, "--existing-secret")
	flags := storageCLIArtifactFlags(t)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock", "--domain", "*.example.com"}, flags...)
	_, err = executeStorageCLI(t, forbiddenStorageFactory(t), args...)
	require.ErrorContains(t, err, "exact lowercase")
	f.mu.Lock()
	require.Zero(t, f.allocations)
	f.mu.Unlock()
	out, err := executeStorageCLI(t, forbiddenStorageFactory(t), "volume", "create", "ordinary", "--size", "30GiB", "--host", "inf13")
	require.NoError(t, err)
	require.Contains(t, out, "ID:")
	require.NotContains(t, out, "CONFIGURED")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 1, f.allocations)
}

func TestStorageUncertainAllocationDoesNotRetry(t *testing.T) {
	f := newStorageCPFixture(t)
	f.allocationFails = true
	configureStorageCLI(t)
	args := append([]string{"volume", "create", "app-data", "--size", "30GiB", "--auto-unlock"}, storageCLIArtifactFlags(t)...)
	fake := &fakeStorageAWS{}
	random := &rejectingRandom{}
	_, err := executeStorageCLI(t, fakeStorageFactory(fake, random), args...)
	require.ErrorContains(t, err, "inspect tinfoil volume list before retrying")
	require.Empty(t, fake.secretIDs)
	require.Zero(t, fake.creates)
	require.Zero(t, random.calls)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 1, f.allocations)
}
