package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/selfupdate"
)

const (
	testUpdateCurrent = "0.18.9"
	testUpdateVersion = "0.19.0"
	testUpdateRelease = `{"tag_name":"v0.19.0","assets":[{"name":"tinfoil-cli_0.19.0_linux_amd64.tar.gz","browser_download_url":"https://github.com/tinfoilsh/tinfoil-cli/releases/download/v0.19.0/tinfoil-cli_0.19.0_linux_amd64.tar.gz"},{"name":"tinfoil-cli_0.19.0_checksums.txt","browser_download_url":"https://github.com/tinfoilsh/tinfoil-cli/releases/download/v0.19.0/tinfoil-cli_0.19.0_checksums.txt"}]}`
)

type selfUpdateRoundTripFunc func(*http.Request) (*http.Response, error)

func (f selfUpdateRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSelfUpdateCheckIsFreshReadOnlyAndUnauthenticated(t *testing.T) {
	setVersionForTest(t, testUpdateCurrent)
	t.Setenv(envNoUpdateCheck, "1")
	t.Setenv("TINFOIL_CONFIG", filepath.Join(t.TempDir(), "absent", "config.json"))
	t.Setenv("TINFOIL_ADMIN_KEY", "not-a-real-admin-key")
	t.Setenv("GITHUB_TOKEN", "not-a-real-github-token")
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, "/repos/tinfoilsh/tinfoil-cli/releases/latest", r.URL.Path)
		require.Equal(t, "tinfoil-cli/"+testUpdateCurrent, r.Header.Get("User-Agent"))
		require.Empty(t, r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("Cookie"))
		_, _ = io.WriteString(w, testUpdateRelease)
	}))
	defer server.Close()
	mirror, err := url.Parse(server.URL)
	require.NoError(t, err)
	newUpdater := func() selfUpdateRunner {
		return selfupdate.NewUpdater(selfupdate.Options{
			Version: version, GOOS: "linux", GOARCH: "amd64",
			Executable: func() (string, error) { t.Fatal("--check inspected target"); return "", nil },
			Transport: selfUpdateRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, "https://api.github.com/repos/tinfoilsh/tinfoil-cli/releases/latest", req.URL.String())
				clone := req.Clone(req.Context())
				clone.URL.Scheme, clone.URL.Host = mirror.Scheme, mirror.Host
				clone.Host = mirror.Host
				return server.Client().Transport.RoundTrip(clone)
			}),
		})
	}
	for range 2 {
		root := &cobra.Command{Use: "tinfoil"}
		root.AddCommand(newSelfUpdateCommand(newUpdater))
		var out, stderr bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&stderr)
		root.SetArgs([]string{"update", "--check", "-o", "json"})
		require.NoError(t, root.Execute())
		var result selfupdate.Result
		require.NoError(t, json.Unmarshal(out.Bytes(), &result))
		require.Equal(t, selfupdate.Result{Current: testUpdateCurrent, Latest: testUpdateVersion, Status: selfupdate.StatusAvailable}, result)
		require.Empty(t, stderr.String())
	}
	require.EqualValues(t, 2, requests.Load())
	_, err = os.Stat(os.Getenv("TINFOIL_CONFIG"))
	require.True(t, os.IsNotExist(err))
}

func TestSelfUpdateCommandResolution(t *testing.T) {
	commandState := newCommandFixture()

	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"update"}, true},
		{[]string{"--verbose", "update", "--check"}, true},
		{[]string{"--repo", "owner/name", "update", "--check"}, true},
		{[]string{"update", "-o", "json"}, true},
		{[]string{"--repo", "update"}, false},
		{[]string{"--repo=update"}, false},
		{[]string{"container", "update", "status", "example"}, false},
		{[]string{"deployment", "update", "example"}, false},
		{[]string{"help", "update"}, false},
		{nil, false},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			require.Equal(t, tt.want, isSelfUpdateCommand(commandState.rootCmd, tt.args))
		})
	}
	for _, args := range [][]string{{"update", "extra"}, {"update", "--output", "xml"}, {"update", "--url", "https://example.com"}} {
		root := &cobra.Command{Use: "tinfoil"}
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.AddCommand(newSelfUpdateCommand(func() selfUpdateRunner { t.Fatal("invalid args invoked updater"); return nil }))
		root.SetArgs(args)
		require.Error(t, root.Execute())
	}
}

type selfUpdateRunFunc func(context.Context, bool) (selfupdate.Result, error)

func (f selfUpdateRunFunc) Run(ctx context.Context, check bool) (selfupdate.Result, error) {
	return f(ctx, check)
}

type failingUpdateWriter struct{}

func (failingUpdateWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }

func TestSelfUpdateReportsResultWriteFailure(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, status := range []string{selfupdate.StatusInstalled, selfupdate.StatusAvailable, selfupdate.StatusCurrent} {
			t.Run(format+"/"+status, func(t *testing.T) {
				result := selfupdate.Result{Current: testUpdateCurrent, Latest: testUpdateVersion, Status: status}
				if status == selfupdate.StatusInstalled {
					result.Path = filepath.Join(t.TempDir(), "tinfoil")
				}
				args := []string{"update", "-o", format}
				if status == selfupdate.StatusAvailable {
					args = append(args, "--check")
				}
				root := &cobra.Command{Use: "tinfoil"}
				root.AddCommand(newSelfUpdateCommand(func() selfUpdateRunner {
					return selfUpdateRunFunc(func(ctx context.Context, check bool) (selfupdate.Result, error) {
						require.Equal(t, status == selfupdate.StatusAvailable, check)
						return result, nil
					})
				}))
				root.SetArgs(args)
				root.SetOut(failingUpdateWriter{})
				root.SetErr(io.Discard)
				err := root.Execute()
				require.ErrorIs(t, err, os.ErrPermission)
				require.ErrorContains(t, err, "writing result failed")
				if status == selfupdate.StatusInstalled {
					require.ErrorContains(t, err, "tinfoil "+testUpdateVersion+" is installed at "+result.Path)
				} else {
					require.ErrorContains(t, err, "no executable was changed")
				}
			})
		}
	}
}
