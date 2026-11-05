package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
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
	monitor := commandAt(t, a, "monitor", "metrics")
	require.NoError(t, monitor.Flags().Set("time", "1h"))
	require.NoError(t, commandAt(t, a, "container", "metrics").Flags().Set("time", "7d"))
	require.False(t, commandAt(t, b, "monitor", "metrics").Flags().Changed("time"))
	a.SetArgs([]string{"monitor", "metrics", monitorID})
	require.NoError(t, a.Execute())
	b.SetArgs([]string{"monitor", "metrics", monitorID})
	require.NoError(t, b.Execute())
	a.SetArgs([]string{"sandbox", "metrics", sandboxID})
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
	a.SetArgs([]string{"monitor", "delete", monitorID, "--yes"})
	require.NoError(t, a.Execute())
	b.SetArgs([]string{"monitor", "delete", monitorID})
	require.Error(t, b.Execute())
	require.Equal(t, 1, deletions)
	require.Contains(t, firstOut.String(), "Deleted Monitor mon")
	require.Empty(t, secondOut.String())
	require.Contains(t, secondErr.String(), "--yes")
	yes, err := commandAt(t, a, "sandbox", "delete").Flags().GetBool("yes")
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
		root := newRootCommandWithDependencies(commandDependencies{version: version, out: &out})
		root.SetArgs([]string{"--version"})
		require.NoError(t, root.Execute())
		require.Equal(t, "tinfoil version "+version+"\n", out.String())
		for _, path := range [][]string{{"ct", "rm"}, {"monitors", "metrics"}, {"sandboxes", "delete"}, {"repo", "secret", "set"}, {"project", "storage"}, {"volume", "auto-unlock"}, {"http", "post"}, {"attestation", "verify"}, {"proxy"}, {"update"}} {
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
		require.Equal(t, status, runCommand(root, nil))
		require.Equal(t, "cleaned up\n", output.String())
	}
	var stderr bytes.Buffer
	root := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return errors.New("failed") }}
	root.SetErr(&stderr)
	require.Equal(t, 1, runCommand(root, nil))
	require.Contains(t, stderr.String(), "Error: failed")
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
