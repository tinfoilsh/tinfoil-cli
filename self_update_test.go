package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	testUpdateVersion = "0.19.0"
	testArchiveName   = "tinfoil-cli_0.19.0_linux_amd64.tar.gz"
	testChecksumName  = "tinfoil-cli_0.19.0_checksums.txt"
	testOriginalCLI   = "original executable"
	testUpdatedCLI    = "updated executable"
	testCLIFileMode   = 0o751
)

type updateTestTransport struct {
	base http.RoundTripper
	url  *url.URL
}

func (t updateTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || (req.URL.Host != "api.github.com" && req.URL.Host != "github.com" && req.URL.Host != "release-assets.githubusercontent.com") {
		return nil, fmt.Errorf("unexpected public update URL %s", req.URL)
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host = t.url.Scheme, t.url.Host
	clone.Host = t.url.Host
	return t.base.RoundTrip(clone)
}

type selfUpdateFixture struct {
	u         *selfUpdater
	target    string
	release   updateRelease
	archive   []byte
	checksums string
	metadata  []byte
	intercept func(http.ResponseWriter, *http.Request) bool
	mu        sync.Mutex
	requests  []string
}

func updateTestArchive(t *testing.T, headers []tar.Header, bodies []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := range headers {
		require.NoError(t, tw.WriteHeader(&headers[i]))
		if headers[i].Typeflag == tar.TypeReg || headers[i].Typeflag == 0 {
			_, err := io.WriteString(tw, bodies[i])
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func updateBinaryArchive(t *testing.T, contents string) []byte {
	t.Helper()
	return updateTestArchive(t, []tar.Header{{Name: updateBinaryName, Mode: 0o7777, Size: int64(len(contents)), Typeflag: tar.TypeReg}}, []string{contents})
}

func newSelfUpdateFixture(t *testing.T) *selfUpdateFixture {
	t.Helper()
	f := &selfUpdateFixture{target: filepath.Join(t.TempDir(), updateBinaryName)}
	require.NoError(t, os.WriteFile(f.target, []byte(testOriginalCLI), testCLIFileMode))
	require.NoError(t, os.Chmod(f.target, testCLIFileMode))
	f.archive = updateBinaryArchive(t, testUpdatedCLI)
	f.setChecksum()
	f.release = updateRelease{TagName: "v" + testUpdateVersion}
	for _, name := range []string{testArchiveName, testChecksumName} {
		f.release.Assets = append(f.release.Assets, updateAsset{Name: name, URL: updateDownloadBase + f.release.TagName + "/" + name})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("update request included credentials")
		}
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			if f.metadata != nil {
				_, _ = w.Write(f.metadata)
			} else {
				_ = json.NewEncoder(w).Encode(f.release)
			}
		case strings.HasSuffix(r.URL.Path, testChecksumName):
			_, _ = io.WriteString(w, f.checksums)
		case strings.HasSuffix(r.URL.Path, testArchiveName):
			_, _ = w.Write(f.archive)
		default:
			t.Errorf("unexpected download path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	mirror, err := url.Parse(server.URL)
	require.NoError(t, err)
	client := updateHTTPClient(updateTimeout)
	client.Transport = updateTestTransport{base: server.Client().Transport, url: mirror}
	f.u = &selfUpdater{
		current: "0.18.9", goos: "linux", goarch: "amd64", http: client,
		executable: func() (string, error) { return f.target, nil }, rename: os.Rename,
		validateExecutable: func(string) error { return nil },
		inspectExecutable:  snapshotExecutable, chown: (*os.File).Chown,
	}
	return f
}

func (f *selfUpdateFixture) setChecksum() {
	f.checksums = fmt.Sprintf("%x  %s\n", sha256.Sum256(f.archive), testArchiveName)
}

func (f *selfUpdateFixture) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *selfUpdateFixture) assertTarget(t *testing.T, want string) {
	t.Helper()
	data, err := os.ReadFile(f.target)
	require.NoError(t, err)
	require.Equal(t, want, string(data))
	entries, err := os.ReadDir(filepath.Dir(f.target))
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), ".tinfoil-update-"), "temporary update left behind")
	}
}

func TestSelfUpdateInstallsVerifiedArchive(t *testing.T) {
	f := newSelfUpdateFixture(t)
	before, err := os.Stat(f.target)
	require.NoError(t, err)
	result, err := f.u.run(context.Background(), false)
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(f.target)
	require.NoError(t, err)
	require.Equal(t, selfUpdateResult{Current: "0.18.9", Latest: testUpdateVersion, Status: updateStatusInstalled, Path: resolved}, result)
	f.assertTarget(t, testUpdatedCLI)
	after, err := os.Stat(f.target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(testCLIFileMode), after.Mode().Perm())
	require.False(t, os.SameFile(before, after), "replacement must use a new inode")
	require.Equal(t, 3, f.requestCount())
}

func TestSelfUpdateCheckIsFreshReadOnlyAndUnauthenticated(t *testing.T) {
	f := newSelfUpdateFixture(t)
	t.Setenv(envNoUpdateCheck, "1")
	t.Setenv("TINFOIL_CONFIG", filepath.Join(t.TempDir(), "absent", "config.json"))
	t.Setenv("TINFOIL_ADMIN_KEY", "not-a-real-admin-key")
	t.Setenv("GITHUB_TOKEN", "not-a-real-github-token")
	f.u.executable = func() (string, error) { t.Fatal("--check inspected target"); return "", nil }
	f.u.rename = func(string, string) error { t.Fatal("--check renamed target"); return nil }
	for range 2 {
		root := newRootCommand()
		root.AddCommand(newSelfUpdateCommand(func() *selfUpdater { return f.u }))
		var out, stderr bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&stderr)
		root.SetArgs([]string{"update", "--check", "-o", "json"})
		require.NoError(t, root.Execute())
		var result selfUpdateResult
		require.NoError(t, json.Unmarshal(out.Bytes(), &result))
		require.Equal(t, updateStatusAvailable, result.Status)
		require.Empty(t, stderr.String())
	}
	require.Equal(t, 2, f.requestCount())
	f.assertTarget(t, testOriginalCLI)
	_, err := os.Stat(os.Getenv("TINFOIL_CONFIG"))
	require.True(t, os.IsNotExist(err))
}

func TestSelfUpdateVersionDecisions(t *testing.T) {
	for _, current := range []string{testUpdateVersion, "v" + testUpdateVersion, "0.20.0", "0.19.0+build"} {
		t.Run(current, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.u.current = current
			result, err := f.u.run(context.Background(), false)
			require.NoError(t, err)
			require.Equal(t, updateStatusCurrent, result.Status)
			require.Equal(t, 1, f.requestCount())
			f.assertTarget(t, testOriginalCLI)
		})
	}
	for _, current := range []string{"dev", "", "garbage"} {
		t.Run(current, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.u.current = current
			_, err := f.u.run(context.Background(), false)
			require.ErrorContains(t, err, "installer")
			require.Zero(t, f.requestCount())
			f.assertTarget(t, testOriginalCLI)
		})
	}
	for _, current := range []string{"v0.18.9", "0.19.0-rc.1"} {
		t.Run(current, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.u.current = current
			result, err := f.u.run(context.Background(), true)
			require.NoError(t, err)
			require.Equal(t, updateStatusAvailable, result.Status)
		})
	}
}

func TestSelfUpdateRejectsBadReleasesAndDownloads(t *testing.T) {
	tests := []struct {
		name string
		edit func(*selfUpdateFixture)
		want string
	}{
		{"draft", func(f *selfUpdateFixture) { f.release.Draft = true }, "non-stable"},
		{"prerelease", func(f *selfUpdateFixture) { f.release.Prerelease = true }, "non-stable"},
		{"prerelease-tag", func(f *selfUpdateFixture) { f.release.TagName = "v0.19.0-rc.1" }, "non-stable"},
		{"invalid-tag", func(f *selfUpdateFixture) { f.release.TagName = "../v0.19.0" }, "invalid"},
		{"short-tag", func(f *selfUpdateFixture) { f.release.TagName = "v0.19" }, "invalid"},
		{"empty-tag", func(f *selfUpdateFixture) { f.release.TagName = "" }, "invalid"},
		{"malformed-metadata", func(f *selfUpdateFixture) { f.metadata = []byte("{") }, "decoding"},
		{"metadata-limit", func(f *selfUpdateFixture) { f.metadata = bytes.Repeat([]byte(" "), updateMetadataLimit+1) }, "exceeds"},
		{"missing-assets", func(f *selfUpdateFixture) { f.release.Assets = nil }, "no asset"},
		{"missing-arch", func(f *selfUpdateFixture) { f.u.goarch = "riscv64" }, "no asset"},
		{"unsupported-os", func(f *selfUpdateFixture) { f.u.goos = "windows" }, "not supported"},
		{"duplicate-asset", func(f *selfUpdateFixture) { f.release.Assets = append(f.release.Assets, f.release.Assets[0]) }, "duplicate"},
		{"wrong-origin", func(f *selfUpdateFixture) { f.release.Assets[0].URL = "https://example.com/asset" }, "untrusted"},
		{"insecure-url", func(f *selfUpdateFixture) {
			f.release.Assets[0].URL = strings.Replace(f.release.Assets[0].URL, "https:", "http:", 1)
		}, "untrusted"},
		{"moving-url", func(f *selfUpdateFixture) {
			f.release.Assets[0].URL = "https://github.com/tinfoilsh/tinfoil-cli/releases/latest/download/" + testArchiveName
		}, "untrusted"},
		{"wrong-tag", func(f *selfUpdateFixture) {
			f.release.Assets[0].URL = strings.Replace(f.release.Assets[0].URL, "v0.19.0", "v0.20.0", 1)
		}, "untrusted"},
		{"wrong-repo", func(f *selfUpdateFixture) {
			f.release.Assets[1].URL = strings.Replace(f.release.Assets[1].URL, "tinfoilsh/", "someone/", 1)
		}, "untrusted"},
		{"missing-checksum", func(f *selfUpdateFixture) { f.checksums = "" }, "missing checksum"},
		{"wrong-checksum", func(f *selfUpdateFixture) { f.checksums = strings.Repeat("0", 64) + "  " + testArchiveName }, "mismatch"},
		{"duplicate-checksum", func(f *selfUpdateFixture) { f.checksums += f.checksums }, "duplicate"},
		{"short-checksum", func(f *selfUpdateFixture) { f.checksums = "abcd  " + testArchiveName }, "invalid SHA-256"},
		{"nonhex-checksum", func(f *selfUpdateFixture) { f.checksums = strings.Repeat("z", 64) + "  " + testArchiveName }, "invalid SHA-256"},
		{"malformed-checksum", func(f *selfUpdateFixture) { f.checksums = "a b " + testArchiveName }, "malformed"},
		{"checksum-trailing-garbage", func(f *selfUpdateFixture) { f.checksums += strings.TrimSpace(f.checksums) + " garbage" }, "duplicate"},
		{"checksum-limit", func(f *selfUpdateFixture) { f.checksums = strings.Repeat(" ", updateChecksumLimit+1) }, "exceeds"},
		{"bad-gzip", func(f *selfUpdateFixture) { f.archive = []byte("not gzip"); f.setChecksum() }, "extracting"},
		{"truncated-gzip", func(f *selfUpdateFixture) { f.archive = f.archive[:len(f.archive)-4]; f.setChecksum() }, "unexpected EOF"},
		{"bad-gzip-trailer", func(f *selfUpdateFixture) { f.archive[len(f.archive)-8] ^= 1; f.setChecksum() }, "invalid checksum"},
		{"rename-denied", func(f *selfUpdateFixture) { f.u.rename = func(string, string) error { return os.ErrPermission } }, "permission"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			tt.edit(f)
			_, err := f.u.run(context.Background(), false)
			require.ErrorContains(t, err, tt.want)
			f.assertTarget(t, testOriginalCLI)
		})
	}
}

func TestSelfUpdatePlatformAssets(t *testing.T) {
	for _, platform := range []string{"linux/386", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"} {
		t.Run(platform, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			parts := strings.Split(platform, "/")
			f.u.goos, f.u.goarch = parts[0], parts[1]
			name := updateAssetPrefix + testUpdateVersion + "_" + strings.ReplaceAll(platform, "/", "_") + ".tar.gz"
			f.release.Assets[0] = updateAsset{Name: name, URL: updateDownloadBase + f.release.TagName + "/" + name}
			result, err := f.u.run(context.Background(), true)
			require.NoError(t, err)
			require.Equal(t, updateStatusAvailable, result.Status)
			require.Equal(t, 1, f.requestCount())
		})
	}
}

func TestSelfUpdateRejectsUnsafeArchives(t *testing.T) {
	for _, name := range []string{"../tinfoil", "/tinfoil", "./tinfoil", "dir/../tinfoil", "dir\\tinfoil", "other"} {
		t.Run(name, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.archive = updateTestArchive(t, []tar.Header{{Name: name, Size: 1}}, []string{"x"})
			f.setChecksum()
			_, err := f.u.run(context.Background(), false)
			require.Error(t, err)
			f.assertTarget(t, testOriginalCLI)
		})
	}
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeDir, tar.TypeFifo} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			f.archive = updateTestArchive(t, []tar.Header{{Name: updateBinaryName, Typeflag: typ, Linkname: "other"}}, []string{""})
			f.setChecksum()
			_, err := f.u.run(context.Background(), false)
			require.Error(t, err)
			f.assertTarget(t, testOriginalCLI)
		})
	}
	for _, contents := range [][]string{{""}, {"x", "y"}} {
		t.Run(fmt.Sprint(contents), func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			var headers []tar.Header
			for _, body := range contents {
				headers = append(headers, tar.Header{Name: updateBinaryName, Size: int64(len(body))})
			}
			f.archive = updateTestArchive(t, headers, contents)
			f.setChecksum()
			_, err := f.u.run(context.Background(), false)
			require.Error(t, err)
			f.assertTarget(t, testOriginalCLI)
		})
	}
	archive := updateTestArchive(t, []tar.Header{{Name: "README", Size: 2048}, {Name: updateBinaryName, Size: 1}}, []string{strings.Repeat("x", 2048), "y"})
	require.Error(t, extractUpdate(context.Background(), archive, io.Discard, 1024), "ignored entries must consume the expanded budget")
	require.NoError(t, extractUpdate(context.Background(), archive, io.Discard, updateExpandedLimit))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: updateBinaryName, Size: updateBinaryLimit + 1}))
	require.NoError(t, gz.Close())
	require.ErrorContains(t, extractUpdate(context.Background(), buf.Bytes(), io.Discard, updateExpandedLimit), "unsupported archive entry")
}

func TestSelfUpdateHTTPFailuresAndCancellation(t *testing.T) {
	for _, stage := range []string{"/releases/latest", testChecksumName, testArchiveName} {
		for _, mode := range []string{"status", "oversize", "timeout", "cancel", "insecure-redirect"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				f := newSelfUpdateFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "timeout" {
					f.u.http.Timeout = 100 * time.Millisecond
				}
				f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
					if !strings.HasSuffix(r.URL.Path, stage) {
						return false
					}
					switch mode {
					case "status":
						w.WriteHeader(http.StatusForbidden)
					case "oversize":
						w.Header().Set("Content-Length", fmt.Sprint(updateArchiveLimit+1))
					case "timeout":
						<-r.Context().Done()
					case "cancel":
						cancel()
					case "insecure-redirect":
						http.Redirect(w, r, "http://github.com/insecure", http.StatusFound)
					}
					return true
				}
				_, err := f.u.run(ctx, false)
				require.Error(t, err)
				if mode == "cancel" {
					require.ErrorIs(t, err, context.Canceled)
				}
				f.assertTarget(t, testOriginalCLI)
			})
		}
	}
}

func TestSelfUpdateChangedTargetAndConcurrentInstall(t *testing.T) {
	for _, change := range []string{"content", "inode", "symlink", "mode"} {
		t.Run(change, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			original, err := snapshotExecutable(context.Background(), f.target)
			require.NoError(t, err)
			switch change {
			case "content":
				require.NoError(t, os.WriteFile(f.target, []byte("newer executable"), testCLIFileMode))
			case "inode":
				other := filepath.Join(t.TempDir(), "other")
				require.NoError(t, os.WriteFile(other, []byte(testOriginalCLI), testCLIFileMode))
				require.NoError(t, os.Rename(other, f.target))
			case "symlink":
				other := filepath.Join(t.TempDir(), "other")
				require.NoError(t, os.WriteFile(other, []byte(testOriginalCLI), testCLIFileMode))
				require.NoError(t, os.Remove(f.target))
				require.NoError(t, os.Symlink(other, f.target))
			case "mode":
				require.NoError(t, os.Chmod(f.target, 0o700))
			}
			err = f.u.install(context.Background(), f.target, original, f.archive)
			require.Error(t, err)
			want := testOriginalCLI
			if change == "content" {
				want = "newer executable"
			}
			f.assertTarget(t, want)
		})
	}
	f := newSelfUpdateFixture(t)
	original, err := snapshotExecutable(context.Background(), f.target)
	require.NoError(t, err)
	dir, err := os.Open(filepath.Dir(f.target))
	require.NoError(t, err)
	require.NoError(t, unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	require.ErrorContains(t, f.u.install(context.Background(), f.target, original, f.archive), "locking installation directory")
	f.assertTarget(t, testOriginalCLI)
	require.NoError(t, dir.Close())
	require.NoError(t, f.u.install(context.Background(), f.target, original, f.archive))
	require.ErrorContains(t, f.u.install(context.Background(), f.target, original, f.archive), "changed during update")
	f.assertTarget(t, testUpdatedCLI)
}

func TestSelfUpdateResolvesSymlinksAndRejectsManagedInstalls(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		f := newSelfUpdateFixture(t)
		link := filepath.Join(t.TempDir(), "linked-cli")
		require.NoError(t, os.Symlink(f.target, link))
		f.u.executable = func() (string, error) { return link, nil }
		_, err := f.u.run(context.Background(), false)
		require.NoError(t, err)
		f.assertTarget(t, testUpdatedCLI)
		info, err := os.Lstat(link)
		require.NoError(t, err)
		require.NotZero(t, info.Mode()&os.ModeSymlink)
	})
	for _, component := range []string{"Cellar", "Caskroom"} {
		t.Run(component, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			rack := filepath.Join(t.TempDir(), component, updateBinaryName)
			keg := filepath.Join(rack, "0.18.9")
			target := filepath.Join(keg, "bin", updateBinaryName)
			require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
			require.NoError(t, os.WriteFile(target, []byte(testOriginalCLI), testCLIFileMode))
			if component == "Cellar" {
				require.NoError(t, os.WriteFile(filepath.Join(keg, "INSTALL_RECEIPT.json"), []byte(`{"homebrew_version":"5.0.0"}`), 0o600))
			} else {
				require.NoError(t, os.MkdirAll(filepath.Join(rack, ".metadata", "0.18.9"), 0o700))
			}
			link := filepath.Join(t.TempDir(), updateBinaryName)
			require.NoError(t, os.Symlink(target, link))
			f.u.executable = func() (string, error) { return link, nil }
			_, err := f.u.run(context.Background(), false)
			require.ErrorContains(t, err, "package manager")
			f.assertTarget(t, testOriginalCLI)
		})
	}
}

func TestSelfUpdatePermissionAndPreparationFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	f := newSelfUpdateFixture(t)
	dir := filepath.Dir(f.target)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0o700)) })
	_, err := f.u.run(context.Background(), false)
	require.ErrorIs(t, err, os.ErrPermission)
	require.ErrorContains(t, err, f.target)
	f.assertTarget(t, testOriginalCLI)
}

func TestSelfUpdateCancellationDuringExtractionAndBeforeRename(t *testing.T) {
	f := newSelfUpdateFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original, err := snapshotExecutable(context.Background(), f.target)
	require.NoError(t, err)
	require.ErrorIs(t, f.u.install(ctx, f.target, original, f.archive), context.Canceled)
	f.assertTarget(t, testOriginalCLI)
	ctx, cancel = context.WithCancel(context.Background())
	writer := &cancelUpdateWriter{cancel: cancel}
	require.ErrorIs(t, extractUpdate(ctx, f.archive, writer, updateExpandedLimit), context.Canceled)
	require.NotZero(t, writer.written)
}

type cancelUpdateWriter struct {
	cancel  context.CancelFunc
	written int
}

func (w *cancelUpdateWriter) Write(p []byte) (int, error) {
	w.written += len(p)
	w.cancel()
	return len(p), nil
}

func TestSelfUpdateCommandResolution(t *testing.T) {
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
			require.Equal(t, tt.want, isSelfUpdateCommand(rootCmd, tt.args))
		})
	}
	for _, args := range [][]string{{"update", "extra"}, {"update", "--output", "xml"}, {"update", "--url", "https://example.com"}} {
		root := newRootCommand()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.AddCommand(newSelfUpdateCommand(func() *selfUpdater { t.Fatal("invalid args invoked updater"); return nil }))
		root.SetArgs(args)
		require.Error(t, root.Execute())
	}
}

func TestSelfUpdateInstalledBinaryRuns(t *testing.T) {
	f := newSelfUpdateFixture(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	binary := filepath.Join(dir, "fixture")
	require.NoError(t, os.WriteFile(source, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"tinfoil version "+testUpdateVersion+"\") }\n"), 0o600))
	cmd := exec.Command("go", "build", "-o", binary, source)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	data, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.ErrorContains(t, verifyRunningExecutable(binary), "does not match the running build")
	f.archive = updateBinaryArchive(t, string(data))
	f.setChecksum()
	_, err = f.u.run(context.Background(), false)
	require.NoError(t, err)
	output, err = exec.Command(f.target, "--version").CombinedOutput()
	require.NoError(t, err, string(output))
	require.Equal(t, "tinfoil version "+testUpdateVersion+"\n", string(output))
}

func TestArchiveChecksumAcceptsPublishedFormats(t *testing.T) {
	want := sha256.Sum256([]byte("archive"))
	for _, line := range []string{fmt.Sprintf("%x  %s\n", want, testArchiveName), fmt.Sprintf("%X *%s\r\n", want, testArchiveName)} {
		got, err := archiveChecksum([]byte("irrelevant other.tar.gz\n"+line), testArchiveName)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
}

func TestUpdateRedirectPolicy(t *testing.T) {
	client := updateHTTPClient(updateTimeout)
	for _, endpoint := range []string{"http://github.com/file", "https://user:password@github.com/file"} {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		require.NoError(t, err)
		require.Error(t, client.CheckRedirect(req, nil))
	}
	req, err := http.NewRequest(http.MethodGet, "https://release-assets.githubusercontent.com/file", nil)
	require.NoError(t, err)
	require.NoError(t, client.CheckRedirect(req, nil))
	require.Error(t, client.CheckRedirect(req, make([]*http.Request, updateMaxRedirects)))
}

func TestExtractUpdatePropagatesWriteErrors(t *testing.T) {
	err := extractUpdate(context.Background(), updateBinaryArchive(t, "binary"), failingUpdateWriter{}, updateExpandedLimit)
	require.ErrorIs(t, err, os.ErrPermission)
}

type failingUpdateWriter struct{}

func (failingUpdateWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }

func TestSelfUpdateTargetLookupError(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.u.executable = func() (string, error) { return "", errors.New("unavailable") }
	_, err := f.u.run(context.Background(), false)
	require.ErrorContains(t, err, "locating running executable")
	require.Equal(t, 1, f.requestCount())
}

func TestSelfUpdateRejectsTruncatedAndConcatenatedTar(t *testing.T) {
	archive := updateBinaryArchive(t, testUpdatedCLI)
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	require.NoError(t, err)
	raw, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"missing-terminator", raw[:len(raw)-1024]},
		{"one-terminator-block", raw[:len(raw)-512]},
		{"partial-body", raw[:512+len(testUpdatedCLI)-1]},
		{"second-tar", append(append([]byte{}, raw...), raw...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, err := zw.Write(tt.data)
			require.NoError(t, err)
			require.NoError(t, zw.Close())
			f.archive = buf.Bytes()
			f.setChecksum()
			_, err = f.u.run(context.Background(), false)
			require.Error(t, err)
			f.assertTarget(t, testOriginalCLI)
		})
	}
	require.Error(t, extractUpdate(context.Background(), append(archive, archive...), io.Discard, updateExpandedLimit))
	var padded bytes.Buffer
	zw := gzip.NewWriter(&padded)
	_, err = zw.Write(append(raw, make([]byte, 1024)...))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, extractUpdate(context.Background(), padded.Bytes(), io.Discard, updateExpandedLimit))
	require.NoError(t, extractUpdate(context.Background(), archive, io.Discard, int64(len(raw))))
	require.Error(t, extractUpdate(context.Background(), archive, io.Discard, int64(len(raw)-1)))
}

func TestSelfUpdateChecksTargetBeforeDownload(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, testChecksumName) {
			if err := os.WriteFile(f.target, []byte("newer executable"), testCLIFileMode); err != nil {
				t.Error(err)
			}
			f.release.TagName = "v0.20.0"
		}
		return false
	}
	_, err := f.u.run(context.Background(), false)
	require.ErrorContains(t, err, "changed during update")
	f.assertTarget(t, "newer executable")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, []string{
		"/repos/tinfoilsh/tinfoil-cli/releases/latest",
		"/tinfoilsh/tinfoil-cli/releases/download/v0.19.0/" + testChecksumName,
		"/tinfoilsh/tinfoil-cli/releases/download/v0.19.0/" + testArchiveName,
	}, f.requests)
}

func TestSelfUpdateCurrentDoesNotRequireWritableInstallation(t *testing.T) {
	f := newSelfUpdateFixture(t)
	f.u.current = testUpdateVersion
	f.u.executable = func() (string, error) { return "", os.ErrPermission }
	result, err := f.u.run(context.Background(), false)
	require.NoError(t, err)
	require.Equal(t, updateStatusCurrent, result.Status)
	f.assertTarget(t, testOriginalCLI)
}

func TestSelfUpdateRejectsUnsafeTargets(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o755 | os.ModeSetuid, 0o755 | os.ModeSetgid, 0o755 | os.ModeSticky} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			require.NoError(t, os.Chmod(f.target, mode))
			_, err := f.u.run(context.Background(), false)
			require.ErrorContains(t, err, "regular executable")
			f.assertTarget(t, testOriginalCLI)
		})
	}
	for _, kind := range []string{"directory", "empty"} {
		t.Run(kind, func(t *testing.T) {
			f := newSelfUpdateFixture(t)
			if kind == "directory" {
				f.u.executable = func() (string, error) { return filepath.Dir(f.target), nil }
			} else {
				require.NoError(t, os.Truncate(f.target, 0))
			}
			_, err := f.u.run(context.Background(), false)
			require.Error(t, err)
		})
	}
}

func TestSelfUpdateRejectsSparseArchiveEntries(t *testing.T) {
	archive := updateTestArchive(t, []tar.Header{{
		Name: updateBinaryName, Size: 1,
		PAXRecords: map[string]string{
			"FOO.sparse.major": "0", "FOO.sparse.minor": "1",
			"FOO.sparse.map": "0,1", "FOO.sparse.numblocks": "1",
			"FOO.sparse.size": fmt.Sprint(updateBinaryLimit),
		},
	}}, []string{"x"})
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	require.NoError(t, err)
	raw, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	// The writer reserves GNU sparse keys; substitute an equal-length namespace in the PAX body.
	raw = bytes.ReplaceAll(raw, []byte("FOO.sparse."), []byte("GNU.sparse."))
	header, err := tar.NewReader(bytes.NewReader(raw)).Next()
	require.NoError(t, err)
	require.Equal(t, int64(updateBinaryLimit), header.Size)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.ErrorContains(t, extractUpdate(context.Background(), buf.Bytes(), io.Discard, updateExpandedLimit), "sparse")
}

func TestVerifyRunningExecutable(t *testing.T) {
	target, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, verifyRunningExecutable(target))
	f := newSelfUpdateFixture(t)
	f.u.validateExecutable = func(string) error { return errors.New("installed executable does not match the running build") }
	_, err = f.u.run(context.Background(), false)
	require.ErrorContains(t, err, "does not match the running build")
	require.Equal(t, 1, f.requestCount())
	f.assertTarget(t, testOriginalCLI)
}
