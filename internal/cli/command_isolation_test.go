package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
)

func commandAt(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	command, rest, err := root.Find(path)
	require.NoError(t, err)
	require.Empty(t, rest)
	return command
}

func commandAPI(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
}

func TestFreshCommandTreesKeepManagedMetricsAndStreamsIndependent(t *testing.T) {
	const monitorID = "11111111-1111-4111-8111-111111111111"
	const sandboxID = "22222222-2222-4222-8222-222222222222"
	var windows []string
	commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/metrics") {
			window := r.URL.Query().Get("time")
			windows = append(windows, window)
			json.NewEncoder(w).Encode(map[string]string{"window": window})
			return
		}
		row := containerView{ID: monitorID, Name: "mon", Repo: monitorRepo}
		if strings.HasSuffix(r.URL.Path, sandboxID) {
			row.ID, row.Name, row.Repo = sandboxID, "work", defaultSandboxRepo
		}
		json.NewEncoder(w).Encode(row)
	})
	var first, second bytes.Buffer
	a := newRootCommandWithDependencies(commandDependencies{out: &first, err: io.Discard})
	b := newRootCommandWithDependencies(commandDependencies{out: &second, err: io.Discard})
	monitor := commandAt(t, a, "perimeter", "metrics")
	require.NoError(t, monitor.Flags().Set("time", "1h"))
	require.NoError(t, commandAt(t, a, "container", "metrics").Flags().Set("time", "7d"))
	require.False(t, commandAt(t, b, "perimeter", "metrics").Flags().Changed("time"))
	a.SetArgs([]string{"perimeter", "metrics", monitorID})
	require.NoError(t, a.Execute())
	b.SetArgs([]string{"perimeter", "metrics", monitorID})
	require.NoError(t, b.Execute())
	a.SetArgs([]string{"bunker", "metrics", sandboxID})
	require.NoError(t, a.Execute())
	require.Equal(t, []string{"1h", "24h", "24h"}, windows)
	require.Contains(t, first.String(), `"window": "1h"`)
	require.NotContains(t, second.String(), "1h")
	require.Contains(t, second.String(), `"window": "24h"`)
}

func TestFreshCommandTreesKeepConfirmationIndependent(t *testing.T) {
	const monitorID = "11111111-1111-4111-8111-111111111111"
	deletions := 0
	commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/context":
			json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: "owner"})
		case "GET /api/containers/" + monitorID:
			json.NewEncoder(w).Encode(containerView{ID: monitorID, Name: "mon", Repo: monitorRepo, ClerkUserID: "owner"})
		case "GET /api/containers":
			io.WriteString(w, "[]")
		case "DELETE /api/monitors/" + monitorID:
			deletions++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	var firstOut, firstErr, secondOut, secondErr bytes.Buffer
	a := newRootCommandWithDependencies(commandDependencies{in: strings.NewReader(""), out: &firstOut, err: &firstErr})
	b := newRootCommandWithDependencies(commandDependencies{in: strings.NewReader(""), out: &secondOut, err: &secondErr})
	a.SetArgs([]string{"perimeter", "delete", monitorID, "--yes"})
	require.NoError(t, a.Execute())
	b.SetArgs([]string{"perimeter", "delete", monitorID})
	require.Error(t, b.Execute())
	require.Equal(t, 1, deletions)
	require.Contains(t, firstOut.String(), "Deleted Monitor mon")
	require.Empty(t, secondOut.String())
	require.Contains(t, secondErr.String(), "--yes")
	yes, err := commandAt(t, a, "bunker", "delete").Flags().GetBool("yes")
	require.NoError(t, err)
	require.False(t, yes)
}

func TestCommandFamiliesKeepOutputFlagsIndependent(t *testing.T) {
	commandAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "[]")
	})
	var out bytes.Buffer
	root := newRootCommandWithDependencies(commandDependencies{out: &out, err: io.Discard})
	require.NoError(t, commandAt(t, root, "container").PersistentFlags().Set("output", "json"))
	root.SetArgs([]string{"domain", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "No custom domains")
}

func TestLocalConfigSnapshotsBelongToTheirInvocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	first := []byte("name: first\n")
	second := []byte("name: second\n")
	require.NoError(t, os.WriteFile(path, first, 0600))
	a, b := &rootOptions{localConfigFile: path}, &rootOptions{localConfigFile: path}
	read, err := readLocalConfig(a)
	require.NoError(t, err)
	require.Equal(t, first, read)
	require.NoError(t, os.WriteFile(path, second, 0600))
	read, err = readLocalConfig(a)
	require.NoError(t, err)
	require.Equal(t, first, read)
	read, err = readLocalConfig(b)
	require.NoError(t, err)
	require.Equal(t, second, read)
}

func TestFreshCommandTreesPreserveHelpAndVersion(t *testing.T) {
	t.Setenv(envConfigPath, t.TempDir())
	for _, version := range []string{"first-build", "second-build"} {
		var out bytes.Buffer
		root := newRootCommandWithDependencies(commandDependencies{
			version: version, out: &out,
			credentials: func() (*auth.Store, error) {
				t.Fatal("help or version accessed credentials")
				return nil, nil
			},
			volumeStore: forbiddenStorageFactory(t),
			openBrowser: func(string) error { t.Fatal("help or version opened a browser"); return nil },
		})
		root.SetArgs([]string{"--version"})
		require.NoError(t, root.Execute())
		require.Equal(t, "tinfoil version "+version+"\n", out.String())
		for _, path := range [][]string{{"ct", "rm"}, {"perimeter", "metrics"}, {"bunker", "delete"}, {"repo", "secret", "set"}, {"project", "storage"}, {"volume", "auto-unlock"}, {"http", "post"}, {"attestation", "verify"}, {"proxy"}, {"update"}} {
			require.NotNil(t, commandAt(t, root, path...))
		}
		out.Reset()
		root.SetArgs([]string{"--help"})
		require.NoError(t, root.Execute())
		require.Contains(t, out.String(), "Available Commands:")
		require.Contains(t, out.String(), "Docs: "+docsBase+"sdk/cli-sdk")
		require.NotContains(t, out.String(), "Run a local HTTP proxy")
	}
}

func TestOldBunkerAndPerimeterCommandNamesAreGone(t *testing.T) {
	root := newRootCommandWithDependencies(commandDependencies{out: io.Discard, err: io.Discard})
	for _, name := range []string{"sandbox", "sandboxes", "monitor", "monitors", "bunkers", "perimeters"} {
		_, _, err := root.Find([]string{name, "status"})
		require.ErrorContains(t, err, "unknown command", name)
	}
}

func TestRunnerReturnsStatusAfterCommandCleanup(t *testing.T) {
	t.Setenv(envNoUpdateCheck, "1")
	for _, status := range []int{0, 17} {
		var output bytes.Buffer
		root := &cobra.Command{Use: "test", RunE: func(cmd *cobra.Command, _ []string) error {
			defer fmt.Fprintln(cmd.OutOrStdout(), "cleaned up")
			return sshExit(status, nil)
		}}
		root.SetOut(&output)
		root.SetErr(&output)
		require.Equal(t, status, runCommand(root, []string{}, nil))
		require.Equal(t, "cleaned up\n", output.String())
	}
	var stderr bytes.Buffer
	root := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return errors.New("failed") }}
	root.SetErr(&stderr)
	require.Equal(t, 1, runCommand(root, []string{}, nil))
	require.Contains(t, stderr.String(), "Error: failed")
}

func TestProcessRunSendsUnknownHelpTopicsToStderr(t *testing.T) {
	t.Setenv(envNoUpdateCheck, "1")
	var status int
	var stdout []byte
	stderr, err := captureTestStderr(func() error {
		var captureErr error
		stdout, captureErr = captureTestStdout(func() error {
			status = Run([]string{"help", "bogus"}, Build{}, nil, os.Stdout, os.Stderr)
			return nil
		})
		return captureErr
	})
	require.NoError(t, err)
	require.Equal(t, 0, status)
	require.Empty(t, string(stdout))
	require.Contains(t, string(stderr), "Unknown help topic")
}

func TestRunnerRoutesAPIErrorHintsToItsErrorStream(t *testing.T) {
	t.Setenv(envNoUpdateCheck, "1")
	commandAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "account limit", "code": containerLimitReached})
	})
	var out, stderr bytes.Buffer
	status := run([]string{"domain", "list"}, commandDependencies{out: &out, err: &stderr})
	require.Equal(t, 1, status)
	require.Empty(t, out.String())
	require.Contains(t, stderr.String(), "Error: account limit")
	require.Equal(t, 1, strings.Count(stderr.String(), accountLimitsHint))
}

func TestRunnerKeepsDeprecationSeparateFromHelp(t *testing.T) {
	t.Setenv(envNoUpdateCheck, "1")
	var output, diagnostic bytes.Buffer
	root := newRootCommandWithDependencies(commandDependencies{out: &output, err: &diagnostic})
	for range 2 {
		require.Zero(t, runCommand(root, []string{"proxy", "--help"}, nil))
	}
	require.Equal(t, 2, strings.Count(output.String(), "Usage:"))
	require.NotContains(t, output.String(), "deprecated")
	require.Equal(t, 2, strings.Count(diagnostic.String(), `Command "proxy" is deprecated`))
}

func TestRunnerPreservesUnknownCommandGuidance(t *testing.T) {
	t.Setenv(envNoUpdateCheck, "1")
	for _, test := range []struct {
		args []string
		path string
	}{
		{[]string{"not-a-command"}, "tinfoil"},
		{[]string{"hep"}, "tinfoil"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			require.Equal(t, 1, run(test.args, commandDependencies{out: &output, err: &diagnostic}))
			require.Empty(t, output.String())
			require.Contains(t, diagnostic.String(), "Error: unknown command")
			require.Contains(t, diagnostic.String(), "Run '"+test.path+" --help' for usage.\n")
		})
	}
}

func TestEachTreeSuppliesItsVersionToUpdateRequests(t *testing.T) {
	var agents []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.Header.Get("User-Agent"))
		assert.Equal(t, "/repos/tinfoilsh/tinfoil-cli/releases/latest", r.URL.Path)
		io.WriteString(w, testUpdateRelease)
	}))
	defer server.Close()
	mirror, err := url.Parse(server.URL)
	require.NoError(t, err)
	transport := selfUpdateRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme, clone.URL.Host, clone.Host = mirror.Scheme, mirror.Host, mirror.Host
		return server.Client().Transport.RoundTrip(clone)
	})
	for _, current := range []string{"0.19.1", "0.20.1"} {
		var output bytes.Buffer
		root := newRootCommandWithDependencies(commandDependencies{version: current, out: &output, err: io.Discard, updateTransport: transport})
		root.SetArgs([]string{"update", "--check", "--output", "json"})
		require.NoError(t, root.Execute())
		var result struct {
			Current string `json:"current_version"`
		}
		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		require.Equal(t, current, result.Current)
	}
	require.Equal(t, []string{"tinfoil-cli/0.19.1", "tinfoil-cli/0.20.1"}, agents)
}

func TestCommandPollingSettingsAreInvocationOwned(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	var mu sync.Mutex
	requests := map[string]int{}
	var cancelFast context.CancelFunc
	commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		agent := r.Header.Get("User-Agent")
		mu.Lock()
		requests[agent]++
		count := requests[agent]
		mu.Unlock()
		if agent == "tinfoil-cli/fast" && count == 2 {
			cancelFast()
		}
		json.NewEncoder(w).Encode(containerView{ID: id, Name: "monitor", Repo: monitorRepo, Status: statusRunning})
	})
	polling := defaultPollingOptions()
	polling.followInterval = time.Hour
	slow := newRootCommandWithDependencies(commandDependencies{version: "slow", polling: polling, out: io.Discard, err: io.Discard})
	polling.followInterval = 0
	fast := newRootCommandWithDependencies(commandDependencies{version: "fast", polling: polling, out: io.Discard, err: io.Discard})
	const deadline = 250 * time.Millisecond
	slowContext, cancelSlow := context.WithTimeout(t.Context(), deadline)
	defer cancelSlow()
	slow.SetContext(slowContext)
	for _, root := range []*cobra.Command{slow, fast} {
		root.SetArgs([]string{"perimeter", "status", id, "--watch"})
	}
	require.ErrorIs(t, slow.Execute(), context.DeadlineExceeded)
	fastContext, cancel := context.WithTimeout(t.Context(), deadline)
	cancelFast = cancel
	defer cancel()
	fast.SetContext(fastContext)
	require.NoError(t, fast.Execute())
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]int{"tinfoil-cli/slow": 1, "tinfoil-cli/fast": 2}, requests)
}
