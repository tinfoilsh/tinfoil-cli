package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	updateHelperEnv     = "TINFOIL_SELF_UPDATE_TEST_HELPER"
	updateHelperReady   = "ready\n"
	updateHelperTimeout = 30 * time.Second
	updateTestCDNURL    = "https://release-assets.githubusercontent.com/cdn/archive"
)

func alternateUpdateGroup(t *testing.T, target string) int {
	t.Helper()
	info, err := os.Stat(target)
	require.NoError(t, err)
	groups, err := os.Getgroups()
	require.NoError(t, err)
	for _, gid := range groups {
		if uint32(gid) != info.Sys().(*syscall.Stat_t).Gid {
			return gid
		}
	}
	t.Skip("no supplementary group different from the fixture's group")
	return 0
}

func TestSelfUpdatePreservesGroupOwnership(t *testing.T) {
	f := newSelfUpdateFixture(t)
	gid := alternateUpdateGroup(t, f.target)
	require.NoError(t, os.Chown(f.target, os.Getuid(), gid))
	require.NoError(t, os.Chmod(f.target, 0o750))
	before, err := os.Stat(f.target)
	require.NoError(t, err)
	_, err = f.u.run(context.Background(), false)
	require.NoError(t, err)
	f.assertTarget(t, testUpdatedCLI)
	after, err := os.Stat(f.target)
	require.NoError(t, err)
	require.Equal(t, before.Sys().(*syscall.Stat_t).Uid, after.Sys().(*syscall.Stat_t).Uid)
	require.Equal(t, before.Sys().(*syscall.Stat_t).Gid, after.Sys().(*syscall.Stat_t).Gid)
	require.Equal(t, before.Mode(), after.Mode())
}

func TestSelfUpdateReportsResultWriteFailure(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, action := range []string{"install", "check", "current"} {
			t.Run(format+"/"+action, func(t *testing.T) {
				f := newSelfUpdateFixture(t)
				args := []string{"update", "-o", format}
				if action == "check" {
					args = append(args, "--check")
				}
				if action == "current" {
					f.u.current = testUpdateVersion
				}
				root := newRootCommand()
				root.AddCommand(newSelfUpdateCommand(func() *selfUpdater { return f.u }))
				root.SetArgs(args)
				root.SetOut(failingUpdateWriter{})
				root.SetErr(io.Discard)
				err := root.Execute()
				require.ErrorIs(t, err, os.ErrPermission)
				require.ErrorContains(t, err, "writing result failed")
				if action == "install" {
					resolved, resolveErr := filepath.EvalSymlinks(f.target)
					require.NoError(t, resolveErr)
					require.ErrorContains(t, err, "tinfoil "+testUpdateVersion+" is installed at "+resolved)
					f.assertTarget(t, testUpdatedCLI)
				} else {
					require.ErrorContains(t, err, "no executable was changed")
					f.assertTarget(t, testOriginalCLI)
				}
			})
		}
	}
}

func TestSelfUpdateAllowsUnmanagedCellarPaths(t *testing.T) {
	for _, layout := range []string{"Cellar/tools/tinfoil", "Cellar/tinfoil/0.18.9/bin/tinfoil", "Caskroom/tools/tinfoil"} {
		t.Run(layout, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			target := filepath.Join(t.TempDir(), layout)
			require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
			require.NoError(t, os.Rename(f.target, target))
			f.target = target
			_, err := f.u.run(context.Background(), false)
			require.NoError(t, err)
			f.assertTarget(t, testUpdatedCLI)
		})
	}
}

func TestSelfUpdateRejectsOwnershipChangedDuringUpdate(t *testing.T) {
	f := newSelfUpdateFixture(t)
	gid := alternateUpdateGroup(t, f.target)
	original, err := snapshotExecutable(context.Background(), f.target)
	require.NoError(t, err)
	require.NoError(t, os.Chown(f.target, os.Getuid(), gid))
	err = f.u.install(context.Background(), f.target, original, f.archive)
	require.ErrorContains(t, err, "executable changed during update")
	f.assertTarget(t, testOriginalCLI)
}

func TestSelfUpdateOwnershipFailurePreservesOriginal(t *testing.T) {
	for _, change := range []string{"uid", "gid"} {
		t.Run(change, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.u.inspectExecutable = func(ctx context.Context, target string) (executableSnapshot, error) {
				snapshot, err := snapshotExecutable(ctx, target)
				if change == "uid" {
					snapshot.owner.uid++
				} else {
					snapshot.owner.gid++
				}
				return snapshot, err
			}
			called := false
			f.u.chown = func(temp *os.File, uid, gid int) error {
				called = true
				info, err := temp.Stat()
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "ownership must be restored before executable permissions")
				owner := info.Sys().(*syscall.Stat_t)
				if change == "uid" {
					require.Equal(t, int(owner.Uid)+1, uid)
					require.Equal(t, int(owner.Gid), gid)
				} else {
					require.Equal(t, int(owner.Uid), uid)
					require.Equal(t, int(owner.Gid)+1, gid)
				}
				return os.ErrPermission
			}
			f.u.rename = func(string, string) error { t.Fatal("ownership failure reached rename"); return nil }
			_, err := f.u.run(context.Background(), false)
			require.True(t, called)
			require.ErrorIs(t, err, os.ErrPermission)
			require.ErrorContains(t, err, "preserving executable ownership")
			require.ErrorContains(t, err, "account with permission")
			f.assertTarget(t, testOriginalCLI)
		})
	}
}

func TestSelfUpdateSkipsUnnecessaryChown(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.u.chown = func(*os.File, int, int) error { t.Fatal("unnecessary chown"); return nil }
	_, err := f.u.run(context.Background(), false)
	require.NoError(t, err)
	f.assertTarget(t, testUpdatedCLI)
}

func TestSelfUpdateCancellationAtCommitBoundary(t *testing.T) {
	f := newSelfUpdateFixture(t)
	original, err := snapshotExecutable(context.Background(), f.target)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := false
	f.u.inspectExecutable = func(ctx context.Context, target string) (executableSnapshot, error) {
		snapshot, err := snapshotExecutable(ctx, target)
		require.NoError(t, err)
		prepared, err := filepath.Glob(filepath.Join(filepath.Dir(target), updateTempPattern))
		require.NoError(t, err)
		require.Len(t, prepared, 1)
		data, err := os.ReadFile(prepared[0])
		require.NoError(t, err)
		require.Equal(t, testUpdatedCLI, string(data))
		reached = true
		cancel()
		return snapshot, nil
	}
	f.u.rename = func(string, string) error { t.Fatal("canceled commit reached rename"); return nil }
	require.ErrorIs(t, f.u.install(ctx, f.target, original, f.archive), context.Canceled)
	require.True(t, reached, "must cancel after preparation and the final target snapshot")
	f.assertTarget(t, testOriginalCLI)
}

func TestSelfUpdateHomebrewKnownLayouts(t *testing.T) {
	for _, prefix := range []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"} {
		for _, kind := range []string{"Cellar", "Caskroom"} {
			for _, version := range []string{"0.18.9", "0.18.9_1", "HEAD-abcdef", "latest"} {
				target := filepath.Join(prefix, kind, "tinfoil", version, "bin", "tinfoil")
				managed, err := homebrewManagedExecutable(target)
				require.NoError(t, err)
				require.True(t, managed, target)
			}
		}
	}
	for _, target := range []string{"/opt/homebrew/Cellar/tools/tinfoil", "/opt/homebrew-other/Cellar/tinfoil/0.18.9/bin/tinfoil", "/usr/local/bin/tinfoil"} {
		managed, err := homebrewManagedExecutable(target)
		require.NoError(t, err)
		require.False(t, managed, target)
	}
}

type selfUpdateRoundTripFunc func(*http.Request) (*http.Response, error)

func (f selfUpdateRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSelfUpdateHTTPSRedirectToCDN(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/cdn/archive" {
			_, _ = w.Write(f.archive)
			return true
		}
		if strings.HasSuffix(r.URL.Path, testArchiveName) {
			http.Redirect(w, r, updateTestCDNURL, http.StatusFound)
			return true
		}
		return false
	}
	transport := f.u.http.Transport
	redirected := false
	f.u.http.Transport = selfUpdateRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == updateTestCDNURL {
			redirected = true
			require.Empty(t, req.Header.Get("Authorization"))
			require.Empty(t, req.Header.Get("Cookie"))
		}
		return transport.RoundTrip(req)
	})
	_, err := f.u.run(context.Background(), false)
	require.NoError(t, err)
	require.True(t, redirected)
	require.Equal(t, 4, f.requestCount())
	f.assertTarget(t, testUpdatedCLI)
}

type selfUpdateClosingBody struct {
	io.ReadCloser
	err    error
	closed bool
}

func (b *selfUpdateClosingBody) Close() error {
	b.closed = true
	return errors.Join(b.ReadCloser.Close(), b.err)
}

func TestSelfUpdateResponseBodyClose(t *testing.T) {
	for _, stage := range []string{"/releases/latest", testChecksumName, testArchiveName} {
		for _, status := range []int{http.StatusOK, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", stage, status), func(t *testing.T) {
				f := newSelfUpdateFixture(t)
				if status != http.StatusOK {
					f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
						if strings.HasSuffix(r.URL.Path, stage) {
							w.WriteHeader(status)
							return true
						}
						return false
					}
				}
				closeErr := errors.New("response close failure")
				transport := f.u.http.Transport
				var body *selfUpdateClosingBody
				f.u.http.Transport = selfUpdateRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					resp, err := transport.RoundTrip(req)
					if err != nil {
						return resp, err
					}
					if strings.HasSuffix(req.URL.Path, stage) {
						body = &selfUpdateClosingBody{ReadCloser: resp.Body, err: closeErr}
						resp.Body = body
					}
					return resp, nil
				})
				_, err := f.u.run(context.Background(), false)
				require.ErrorIs(t, err, closeErr)
				require.ErrorContains(t, err, "closing update response")
				if status != http.StatusOK {
					require.ErrorContains(t, err, "unexpected HTTP status 403")
				}
				require.NotNil(t, body)
				require.True(t, body.closed)
				f.assertTarget(t, testOriginalCLI)
			})
		}
	}
}

func TestSelfUpdateStaleProcessBeforeSnapshot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "old-cli")
	replacement := filepath.Join(dir, "new-cli")
	for _, build := range []struct{ path, version string }{{target, "0.18.9"}, {replacement, "0.20.0"}} {
		cmd := exec.Command("go", "test", "-c", "-ldflags", "-X main.version="+build.version, "-o", build.path, ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	newBytes, err := os.ReadFile(replacement)
	require.NoError(t, err)
	want := sha256.Sum256(newBytes)
	ctx, cancel := context.WithTimeout(context.Background(), updateHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, target, "-test.run=^TestSelfUpdateStaleProcessHelper$", "-test.timeout=20s")
	cmd.Env = append(os.Environ(), updateHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	})
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, updateHelperReady, ready)
	require.NoError(t, os.Rename(replacement, target))
	_, err = stdin.Write([]byte{1})
	require.NoError(t, err)
	require.NoError(t, stdin.Close())
	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, cmd.Wait(), string(out)+stderr.String())
	require.Contains(t, string(out), "PASS")
	installed, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, want, sha256.Sum256(installed))
}

func TestSelfUpdateStaleProcessHelper(t *testing.T) {
	if os.Getenv(updateHelperEnv) != "1" {
		return
	}
	_, err := fmt.Fprint(os.Stdout, updateHelperReady)
	require.NoError(t, err)
	var signal [1]byte
	_, err = io.ReadFull(os.Stdin, signal[:])
	require.NoError(t, err)
	u := &selfUpdater{executable: os.Executable, inspectExecutable: snapshotExecutable, validateExecutable: verifyRunningExecutable}
	_, _, err = u.snapshot(context.Background())
	require.ErrorContains(t, err, "installed executable does not match the running build")
}
