package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
)

const (
	selfUpdateName        = "update"
	updateDownloadBase    = "https://github.com/tinfoilsh/tinfoil-cli/releases/download/"
	updateBinaryName      = "tinfoil"
	updateAssetPrefix     = "tinfoil-cli_"
	updateTempPattern     = ".tinfoil-update-*"
	updateTarBlockSize    = 512
	updateSparsePrefix    = "GNU.sparse."
	updateTimeout         = 2 * time.Minute
	updateMaxRedirects    = 10
	updateMetadataLimit   = 1 << 20
	updateChecksumLimit   = 1 << 20
	updateArchiveLimit    = 64 << 20
	updateBinaryLimit     = 96 << 20
	updateExpandedLimit   = 128 << 20
	updateExecutableBits  = 0o111
	updateStatusAvailable = "available"
	updateStatusCurrent   = "up-to-date"
	updateStatusInstalled = "installed"
)

type updateRelease struct {
	TagName    string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []updateAsset `json:"assets"`
}

type updateAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type selfUpdater struct {
	current, goos, goarch string
	http                  *http.Client
	executable            func() (string, error)
	validateExecutable    func(string) error
	rename                func(string, string) error
}

type selfUpdateResult struct {
	Current string `json:"current_version"`
	Latest  string `json:"latest_version"`
	Status  string `json:"status"`
}

func init() {
	rootCmd.AddCommand(newSelfUpdateCommand(func() *selfUpdater {
		return &selfUpdater{
			current: version, goos: runtime.GOOS, goarch: runtime.GOARCH,
			http: updateHTTPClient(updateTimeout), executable: os.Executable, rename: os.Rename,
			validateExecutable: verifyRunningExecutable,
		}
	}))
}

func newSelfUpdateCommand(newUpdater func() *selfUpdater) *cobra.Command {
	var check bool
	var output string
	cmd := &cobra.Command{
		Use: selfUpdateName, Short: "Update the CLI to the latest stable release (no login required)",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf("unsupported output format %q: use text or json", output)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			result, err := newUpdater().run(ctx, check)
			if err != nil {
				return err
			}
			if output == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
			}
			switch result.Status {
			case updateStatusInstalled:
				cmd.Printf("Updated tinfoil from %s to %s.\n", result.Current, result.Latest)
			case updateStatusAvailable:
				cmd.Printf("Update available: %s -> %s. Run: %s\n", result.Current, result.Latest, updateCommand)
			default:
				cmd.Printf("tinfoil %s is up to date (latest stable: %s); no downgrade performed.\n", result.Current, result.Latest)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check fresh release metadata without downloading or changing files")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text or json")
	return cmd
}

func isSelfUpdateCommand(root *cobra.Command, args []string) bool {
	cmd, _, err := root.Find(args)
	return err == nil && cmd.Parent() == root && cmd.Name() == selfUpdateName
}

func updateHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("update redirects must use HTTPS without credentials")
		}
		if len(via) >= updateMaxRedirects {
			return errors.New("too many update redirects")
		}
		return nil
	}}
}

func fetchUpdateRelease(ctx context.Context, client *http.Client, endpoint, current string) (updateRelease, error) {
	data, err := fetchUpdateData(ctx, client, endpoint, current, updateMetadataLimit)
	if err != nil {
		return updateRelease{}, fmt.Errorf("fetching latest release: %w", err)
	}
	var release updateRelease
	if err := json.Unmarshal(data, &release); err != nil {
		return release, fmt.Errorf("decoding latest release: %w", err)
	}
	v := "v" + strings.TrimPrefix(release.TagName, "v")
	if !semver.IsValid(v) || semver.Canonical(v)+semver.Build(v) != v ||
		release.Draft || release.Prerelease || semver.Prerelease(v) != "" {
		return release, fmt.Errorf("latest release has invalid or non-stable tag %q", release.TagName)
	}
	return release, nil
}

func fetchUpdateData(ctx context.Context, client *http.Client, endpoint, current string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", controlplaneUserAgentPrefix+current)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("download exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download exceeds %d bytes", limit)
	}
	return data, nil
}

func (r updateRelease) assetURL(name string) (string, error) {
	expected := updateDownloadBase + url.PathEscape(r.TagName) + "/" + url.PathEscape(name)
	var found string
	for _, asset := range r.Assets {
		if asset.Name != name {
			continue
		}
		if found != "" || asset.URL != expected {
			return "", fmt.Errorf("duplicate or untrusted release asset %q", name)
		}
		found = asset.URL
	}
	if found == "" {
		return "", fmt.Errorf("release %s has no asset %q for this platform", r.TagName, name)
	}
	return found, nil
}

func (u *selfUpdater) run(ctx context.Context, check bool) (selfUpdateResult, error) {
	result := selfUpdateResult{Current: u.current}
	if !semver.IsValid("v" + strings.TrimPrefix(u.current, "v")) {
		return result, fmt.Errorf("cannot update unknown/source version %q; use the installer or rebuild from source", u.current)
	}
	if u.goos != "linux" && u.goos != "darwin" {
		return result, fmt.Errorf("self-update is not supported on %s/%s", u.goos, u.goarch)
	}
	var target string
	var original executableSnapshot
	var targetErr error
	if !check {
		target, original, targetErr = u.snapshot(ctx)
	}
	release, err := fetchUpdateRelease(ctx, u.http, latestReleaseURL, u.current)
	if err != nil {
		return result, err
	}
	result.Latest = strings.TrimPrefix(release.TagName, "v")
	if !isNewerVersion(u.current, result.Latest) {
		result.Status = updateStatusCurrent
		return result, nil
	}
	prefix := updateAssetPrefix + result.Latest
	archiveName := prefix + "_" + u.goos + "_" + u.goarch + ".tar.gz"
	archiveURL, err := release.assetURL(archiveName)
	if err != nil {
		return result, err
	}
	checksumURL, err := release.assetURL(prefix + "_checksums.txt")
	if err != nil {
		return result, err
	}
	result.Status = updateStatusAvailable
	if check {
		return result, nil
	}
	if targetErr != nil {
		return result, targetErr
	}
	checksums, err := fetchUpdateData(ctx, u.http, checksumURL, u.current, updateChecksumLimit)
	if err != nil {
		return result, fmt.Errorf("downloading checksums: %w", err)
	}
	expected, err := archiveChecksum(checksums, archiveName)
	if err != nil {
		return result, err
	}
	archive, err := fetchUpdateData(ctx, u.http, archiveURL, u.current, updateArchiveLimit)
	if err != nil {
		return result, fmt.Errorf("downloading update: %w", err)
	}
	if sha256.Sum256(archive) != expected {
		return result, errors.New("update archive SHA-256 checksum mismatch")
	}
	if err := u.install(ctx, target, original, archive); err != nil {
		return result, fmt.Errorf("cannot replace %s: %w; use your installer or an account with permission to replace this executable", target, err)
	}
	result.Status = updateStatusInstalled
	return result, nil
}

func (u *selfUpdater) snapshot(ctx context.Context) (string, executableSnapshot, error) {
	var snapshot executableSnapshot
	target, err := u.executable()
	if err != nil {
		return "", snapshot, fmt.Errorf("locating running executable: %w", err)
	}
	target, err = filepath.EvalSymlinks(target)
	if err != nil {
		return "", snapshot, fmt.Errorf("resolving running executable: %w", err)
	}
	if strings.Contains(target, "/Cellar/") || strings.Contains(target, "/Caskroom/") {
		return target, snapshot, fmt.Errorf("%s is managed by Homebrew; update it with your package manager", target)
	}
	snapshot, err = snapshotExecutable(ctx, target)
	if err != nil {
		return target, snapshot, fmt.Errorf("inspecting %s: %w; use your installer or an account with permission to read this executable", target, err)
	}
	if err := u.validateExecutable(target); err != nil {
		return target, snapshot, err
	}
	return target, snapshot, nil
}

func verifyRunningExecutable(target string) error {
	running, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("running build metadata is unavailable; use the installer")
	}
	installed, err := buildinfo.ReadFile(target)
	if err != nil {
		return fmt.Errorf("reading installed build metadata: %w; use the installer", err)
	}
	if !reflect.DeepEqual(running, installed) {
		return errors.New("installed executable does not match the running build; retry from the installed CLI")
	}
	return nil
}

func archiveChecksum(data []byte, name string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		matches := false
		for _, field := range fields {
			matches = matches || strings.TrimPrefix(field, "*") == name
		}
		if !matches {
			continue
		}
		if found || len(fields) != 2 {
			return digest, fmt.Errorf("duplicate or malformed checksum for %s", name)
		}
		if len(fields[0]) != hex.EncodedLen(sha256.Size) {
			return digest, fmt.Errorf("invalid SHA-256 checksum for %s", name)
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return digest, fmt.Errorf("invalid SHA-256 checksum for %s", name)
		}
		copy(digest[:], decoded)
		found = true
	}
	if !found {
		return digest, fmt.Errorf("missing checksum for %s", name)
	}
	return digest, nil
}

type executableSnapshot struct {
	info os.FileInfo
	hash [sha256.Size]byte
}

func snapshotExecutable(ctx context.Context, target string) (snapshot executableSnapshot, err error) {
	info, err := os.Lstat(target)
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&updateExecutableBits == 0 {
		return snapshot, errors.New("target must be a regular executable without special permission bits")
	}
	f, err := os.Open(target)
	if err != nil {
		return snapshot, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	opened, err := f.Stat()
	if err != nil {
		return snapshot, err
	}
	if !os.SameFile(info, opened) {
		return snapshot, errors.New("executable changed while opening; retry from the installed CLI")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(updateContextReader{ctx, f}, updateBinaryLimit+1))
	if err != nil {
		return snapshot, err
	}
	if n == 0 || n > updateBinaryLimit {
		return snapshot, errors.New("existing executable is empty or exceeds the update size limit")
	}
	snapshot.info = info
	copy(snapshot.hash[:], h.Sum(nil))
	return snapshot, nil
}

type updateContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r updateContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func (u *selfUpdater) install(ctx context.Context, target string, original executableSnapshot, archive []byte) (err error) {
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dir.Close(); closeErr != nil {
			// A successful rename is still an installed update if releasing the lock fails.
			log.WithError(closeErr).Warn("closing update directory")
		}
	}()
	// Lock the directory, not the replaced inode; closing it also releases the lock after a crash.
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("locking installation directory (another update may be running): %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(target), updateTempPattern)
	if err != nil {
		return err
	}
	closed, installed := false, false
	defer func() {
		if !closed {
			err = errors.Join(err, temp.Close())
		}
		if !installed {
			err = errors.Join(err, os.Remove(temp.Name()))
		}
	}()
	if err := extractUpdate(ctx, archive, temp, updateExpandedLimit); err != nil {
		return fmt.Errorf("extracting update: %w", err)
	}
	if err := temp.Chmod(original.info.Mode().Perm()); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	err = temp.Close()
	closed = true
	if err != nil {
		return err
	}
	current, err := snapshotExecutable(ctx, target)
	if err != nil {
		return err
	}
	if !os.SameFile(original.info, current.info) || original.hash != current.hash || original.info.Mode() != current.info.Mode() {
		return errors.New("executable changed during update; retry from the installed CLI")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := u.rename(temp.Name(), target); err != nil {
		return err
	}
	installed = true
	return nil
}

func extractUpdate(ctx context.Context, archive []byte, dst io.Writer, expandedLimit int64) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer gz.Close()
	decoded := &io.LimitedReader{R: updateContextReader{ctx, gz}, N: expandedLimit + 1}
	tr := tar.NewReader(decoded)
	found := false
	var padding int64
	for {
		before := decoded.N
		hdr, err := tr.Next()
		if err == io.EOF {
			if before-decoded.N != padding+2*updateTarBlockSize {
				return errors.New("missing tar end-of-archive blocks")
			}
			break
		}
		if err != nil {
			return err
		}
		if !path.IsAbs(hdr.Name) && path.Clean(hdr.Name) == hdr.Name && filepath.IsLocal(hdr.Name) && !strings.Contains(hdr.Name, "\\") {
			if hdr.Typeflag != tar.TypeReg || hdr.Size < 0 || hdr.Size > updateBinaryLimit {
				return fmt.Errorf("unsupported archive entry %q", hdr.Name)
			}
		} else {
			return fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		for key := range hdr.PAXRecords {
			if strings.HasPrefix(key, updateSparsePrefix) {
				return errors.New("sparse update archive entries are not supported")
			}
		}
		padding = (updateTarBlockSize - hdr.Size%updateTarBlockSize) % updateTarBlockSize
		out := io.Writer(io.Discard)
		if hdr.Name == updateBinaryName {
			if found || hdr.Size == 0 {
				return errors.New("duplicate or empty tinfoil archive member")
			}
			found = true
			out = dst
		}
		if _, err := io.Copy(out, updateContextReader{ctx, tr}); err != nil {
			return err
		}
	}
	// Drain through gzip EOF to verify its trailer and count even data after the tar terminator.
	if _, err := io.Copy(updateTarPadding{}, decoded); err != nil {
		return err
	}
	if decoded.N == 0 {
		return fmt.Errorf("expanded archive exceeds %d bytes", expandedLimit)
	}
	if !found {
		return errors.New("archive has no regular tinfoil member")
	}
	return ctx.Err()
}

type updateTarPadding struct{}

func (updateTarPadding) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, errors.New("unexpected data after tar end-of-archive blocks")
		}
	}
	return len(p), nil
}
