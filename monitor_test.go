package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
)

const testMonitorTemplate = "containers:\n  - name: monitor\n    env: [MONITOR_OWNER_KEY_SHA256, TINFOIL_STORAGE_BUCKET, AWS_CONTAINER_CREDENTIALS_FULL_URI]\n    command: [-production]\n"

func renderedMonitorConfig(template, digest string) containerView {
	binding := &containerObjectStorage{ID: "6135b835-902c-474f-ae9b-ab8d103fbedd", BucketURL: "s3://test-bucket?region=us-west-2&prefix=containers/account/6135b835-902c-474f-ae9b-ab8d103fbedd/", CredentialsURL: "https://api.test/api/deployments/storage-credentials"}
	raw, err := renderTemplateEnv([]byte(template), map[string]string{monitorOwnerEnv: digest, "TINFOIL_STORAGE_BUCKET": binding.BucketURL, "AWS_CONTAINER_CREDENTIALS_FULL_URI": binding.CredentialsURL})
	if err != nil {
		panic(err)
	}
	return containerView{ObjectStorage: binding, ID: "container-1", Name: "personal", Status: statusRunning, Domain: "personal.user-1.users.monitors.tinfoil.dev", Config: string(raw), ConfigName: monitorConfigPrefix + storageHash(raw), Repo: monitorTemplateRepo, CurrentTag: "v1"}
}

func TestVerifyMonitorConfigRequiresOwnRendering(t *testing.T) {
	for _, env := range []string{"'MONITOR_OWNER_KEY_SHA256=default-owner'", "{MONITOR_OWNER_KEY_SHA256: default-owner}"} {
		template := strings.Replace(testMonitorTemplate, "MONITOR_OWNER_KEY_SHA256", env, 1)
		digest := storageHash([]byte("owner"))
		_, err := verifyMonitorConfig(renderedMonitorConfig(template, digest), digest, []byte(template))
		require.NoError(t, err)
	}
	digest, other := storageHash([]byte("owner")), storageHash([]byte("other"))
	row := renderedMonitorConfig(testMonitorTemplate, digest)
	source, err := verifyMonitorConfig(row, digest, []byte(testMonitorTemplate))
	require.NoError(t, err)
	repo, revision, pinned, err := verify.ParseReference(source)
	require.NoError(t, err)
	hash := storageHash([]byte(row.Config))
	require.Equal(t, []string{"tinfoil/containers", hash, hash}, []string{repo, revision, pinned})
	_, err = newVerifiedClient(row.Domain, source, "")
	require.NoError(t, err)
	for _, config := range []string{renderedMonitorConfig(testMonitorTemplate, other).Config, row.Config + "debug: true\n"} {
		changed := row
		changed.Config = config
		_, err := verifyMonitorConfig(changed, digest, []byte(testMonitorTemplate))
		require.Error(t, err)
	}
	_, err = verifyMonitorConfig(row, digest, []byte(strings.Replace(testMonitorTemplate, "env: [MONITOR_OWNER_KEY_SHA256, TINFOIL_STORAGE_BUCKET, AWS_CONTAINER_CREDENTIALS_FULL_URI]", "env: [MONITOR_OWNER_KEY_SHA256, MONITOR_OWNER_KEY_SHA256, TINFOIL_STORAGE_BUCKET, AWS_CONTAINER_CREDENTIALS_FULL_URI]", 1)))
	require.ErrorContains(t, err, "exactly once")
	changed := row
	binding := *row.ObjectStorage
	binding.BucketURL = strings.Replace(binding.BucketURL, "test-bucket", "other-bucket", 1)
	changed.ObjectStorage = &binding
	_, err = verifyMonitorConfig(changed, digest, []byte(testMonitorTemplate))
	require.ErrorContains(t, err, "storage binding")
}

type monitorCPFixture struct {
	server     *httptest.Server
	exists     bool
	digests    []string
	storageIDs []string
	tags       []string
	template   string
	starts     int
	mutate     func(*containerView)
}

func newMonitorCPFixture(t *testing.T) *monitorCPFixture {
	previousTag := monitorTag
	monitorTag = "v1"
	t.Cleanup(func() { monitorTag = previousTag })
	f := &monitorCPFixture{}
	row := func() containerView {
		template := f.template
		if template == "" {
			template = testMonitorTemplate
		}
		view := renderedMonitorConfig(template, f.digests[0])
		if len(f.tags) > 0 {
			view.CurrentTag = f.tags[len(f.tags)-1]
		}
		if f.mutate != nil {
			f.mutate(&view)
		}
		return view
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /" + monitorTemplateRepo + "/v1/" + monitorTemplateFile:
			io.WriteString(w, testMonitorTemplate)
		case "GET /api/containers":
			rows := []containerView{}
			if f.exists {
				rows = append(rows, row())
			}
			json.NewEncoder(w).Encode(rows)
		case "GET /api/containers/container-1":
			json.NewEncoder(w).Encode(row())
		case "POST /api/containers":
			var request struct {
				Repo          string            `json:"repo"`
				Tag           string            `json:"tag"`
				Variables     map[string]string `json:"variables"`
				ObjectStorage struct {
					ID string `json:"id"`
				} `json:"object_storage"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			require.Equal(t, monitorTemplateRepo, request.Repo)
			require.NotEmpty(t, request.Tag)
			f.tags = append(f.tags, request.Tag)
			f.exists = true
			f.digests = append(f.digests, request.Variables[monitorOwnerEnv])
			f.storageIDs = append(f.storageIDs, request.ObjectStorage.ID)
			json.NewEncoder(w).Encode(row())
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func TestProvisionMonitorReusesRetainedStorageAndGeneration(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	f := newMonitorCPFixture(t)
	client := newCPClient(cliConfig{ControlplaneURL: f.server.URL, APIKey: "admin_test"})
	scope := accountScope{ControlplaneURL: f.server.URL, UserID: "user_1"}
	require.NoError(t, provisionMonitor(client, scope, "personal", f.server.URL))
	dir, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	profile, err := updateProfile(dir, func(p *monitorProfile) error { p.Generation = 42; return nil })
	require.NoError(t, err)
	require.Equal(t, "6135b835-902c-474f-ae9b-ab8d103fbedd", profile.StorageID)
	f.exists = false
	require.NoError(t, provisionMonitor(client, scope, "personal", f.server.URL))
	require.Equal(t, []string{"", profile.StorageID}, f.storageIDs)
	var saved monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileName), &saved))
	require.Equal(t, profile, saved, "reprovisioning must preserve the minimum generation and measured config")
}

func TestProvisionMonitorResumesWithTheSameOwnerSecret(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	f := newMonitorCPFixture(t)
	client := newCPClient(cliConfig{ControlplaneURL: f.server.URL, APIKey: "admin_test"})
	scope := accountScope{ControlplaneURL: f.server.URL, UserID: "user_1"}

	require.NoError(t, provisionMonitor(client, scope, "personal", f.server.URL))
	dir, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	owner, err := loadOwnerKey(dir)
	require.NoError(t, err)
	require.NoError(t, provisionMonitor(client, scope, "personal", f.server.URL), "a retry resumes the same Monitor")
	again, err := loadOwnerKey(dir)
	require.NoError(t, err)
	require.Equal(t, owner, again)
	require.Equal(t, []string{storageHash(owner)}, f.digests)
	require.Zero(t, f.starts)
	var profile monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileName), &profile))
	expectedSource, err := verifyMonitorConfig(renderedMonitorConfig(testMonitorTemplate, storageHash(owner)), storageHash(owner), []byte(testMonitorTemplate))
	require.NoError(t, err)
	require.Equal(t, expectedSource, profile.Source)
	_, err = updateProfile(dir, func(p *monitorProfile) error { p.Device = "device-registered"; return nil })
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, monitorDeviceKeyName)))
	require.ErrorContains(t, provisionMonitor(client, scope, "personal", f.server.URL), "device-registered")
	require.NoFileExists(t, filepath.Join(dir, monitorDeviceKeyName), "a registered device key is never remade")

	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	err = provisionMonitor(client, scope, "personal", f.server.URL)
	require.ErrorContains(t, err, "tinfoil monitor import", "lost credentials never mint a replacement owner")
	lost, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	require.NoFileExists(t, filepath.Join(lost, monitorOwnerKeyName))
	require.Len(t, f.digests, 1)

	f.exists, f.digests, f.starts = false, nil, 0
	f.mutate = func(v *containerView) { v.Config += "debug: true\n" }
	err = provisionMonitor(client, scope, "personal", f.server.URL)
	require.ErrorContains(t, err, "does not match the template, owner key and storage binding")
	require.NoFileExists(t, filepath.Join(lost, monitorProfileName))
	require.Zero(t, f.starts, "an unverified Monitor is never started")
}

func TestMonitorProfileGenerationNeverDecreases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		generation, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		require.NoError(t, err)
		json.NewEncoder(w).Encode(map[string]any{"generation": generation})
	}))
	defer server.Close()
	dir := t.TempDir()
	session := func(generation uint64) *monitorSession {
		return &monitorSession{dir: dir, profile: monitorProfile{Name: "personal", Generation: generation}, url: server.URL, http: server.Client(), owner: make([]byte, monitorOwnerKeyBytes)}
	}
	saved := func() uint64 {
		var profile monitorProfile
		require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileName), &profile))
		return profile.Generation
	}
	require.NoError(t, session(0).call("/5", nil))
	require.ErrorContains(t, session(5).call("/3", nil), "rolled-back")
	require.EqualValues(t, 5, saved())

	var wg sync.WaitGroup
	for generation := 1; generation <= 32; generation++ {
		wg.Go(func() {
			m := session(0)
			if assert.NoError(t, m.call("/"+strconv.Itoa(generation), nil)) {
				assert.GreaterOrEqual(t, m.profile.Generation, uint64(generation))
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 32, saved(), "concurrent commands never lower the saved generation")

	unlock, err := acquireStorageLock(filepath.Join(dir, monitorProfileName))
	require.NoError(t, err)
	require.ErrorContains(t, session(0).call("/40", nil), "locked", "a command waits for the profile lock and never writes around it")
	unlock()
	require.EqualValues(t, 32, saved())
}

func TestMonitorExportImportKeepsScopeAndKeys(t *testing.T) {
	org := "org_1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/auth/context", r.URL.Path)
		io.WriteString(w, `{"context_type":"organization","organization":{"id":"`+org+`"},"user_id":"user_1"}`)
	}))
	defer server.Close()
	t.Setenv(envAdminKey, "admin_test")
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: server.URL, OrgID: org, UserID: "user_1"}
	dir, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	require.NoError(t, prepareStorageDirectory(dir))
	owner := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, monitorOwnerKeyBytes))
	require.NoError(t, writeNewFile(filepath.Join(dir, monitorOwnerKeyName), []byte(owner)))
	require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileName), monitorProfile{Scope: scope, Name: "personal", Domain: "personal.example", Source: "tinfoil/containers@a@sha256:a", Generation: 7, Device: "device-exporter"}, true))
	_, err = ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	work, err := containedKeys("work", sandboxBinding{scope, "personal"}, true)
	require.NoError(t, err)
	_, err = ensureSandboxKeys("uncontained")
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "personal.json")
	require.NoError(t, monitorExportCmd.RunE(monitorExportCmd, []string{"personal", file}))
	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	var export monitorExport
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &export))
	require.Len(t, export.Sandboxes, 1, "only sandboxes bound to this Monitor and account")

	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	require.NoError(t, monitorImportCmd.RunE(monitorImportCmd, []string{file}))
	require.NoError(t, monitorImportCmd.RunE(monitorImportCmd, []string{file}), "importing the same keys again changes nothing")
	restored, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	saved, err := os.ReadFile(filepath.Join(restored, monitorOwnerKeyName))
	require.NoError(t, err)
	require.Equal(t, owner, string(saved))
	require.NoFileExists(t, filepath.Join(restored, monitorDeviceKeyName))
	var profile monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(restored, monitorProfileName), &profile))
	require.EqualValues(t, 7, profile.Generation)
	require.Empty(t, profile.Device, "a new device registers its own key")
	keys, err := containedKeys("work", sandboxBinding{scope, "personal"}, false)
	require.NoError(t, err)
	require.Equal(t, []string{work.diskKey, work.publicKey, work.agentKey}, []string{keys.diskKey, keys.publicKey, keys.agentKey})

	require.NoError(t, os.WriteFile(filepath.Join(keys.dir, sandboxDiskKeyName), []byte(base64.StdEncoding.EncodeToString(make([]byte, sandboxDiskKeyBytes))), 0o600))
	require.ErrorContains(t, monitorImportCmd.RunE(monitorImportCmd, []string{file}), "already holds a different key")
	org = "org_2"
	require.ErrorContains(t, monitorImportCmd.RunE(monitorImportCmd, []string{file}), "another account")
}

// TestMonitorSessionAgainstRealMonitor runs the owner client and the device
// route against the sibling Monitor checkout in production mode.
func TestMonitorSessionAgainstRealMonitor(t *testing.T) {
	source, err := filepath.Abs(filepath.Join("..", "monitor"))
	require.NoError(t, err)
	if _, err := os.Stat(filepath.Join(source, "routes.go")); err != nil {
		t.Skip("no Monitor checkout with routes next to tinfoil-cli")
	}
	shipped, err := os.ReadFile(filepath.Join(source, monitorTemplateFile))
	require.NoError(t, err)
	_, err = verifyMonitorConfig(renderedMonitorConfig(string(shipped), storageHash([]byte("owner"))), storageHash([]byte("owner")), shipped)
	require.NoError(t, err, "the shipped template renders as the CLI expects")
	binary := filepath.Join(t.TempDir(), "monitor")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir, build.Env = source, append(os.Environ(), "GOWORK=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building Monitor: %v\n%s", err, output)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(hostPrivate, "")
	require.NoError(t, err)
	hostKeyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0o600))
	owner := bytes.Repeat([]byte{9}, monitorOwnerKeyBytes)
	bucket, api, sshAddress := t.TempDir(), freeAddress(t), freeAddress(t)
	start := func() *exec.Cmd {
		cmd := exec.Command(binary, "-production", "-ssh-host-key", hostKeyPath,
			"-bucket", "file://"+bucket+"?no_tmp_dir=1", "-api", api, "-listen", sshAddress)
		cmd.Env = append(os.Environ(), "MONITOR_OWNER_KEY_SHA256="+storageHash(owner))
		var logs bytes.Buffer
		cmd.Stderr = &logs
		require.NoError(t, cmd.Start())
		t.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				t.Log(logs.String())
			}
		})
		require.Eventually(t, func() bool {
			resp, err := http.Get("http://" + api + "/healthz")
			if err == nil {
				resp.Body.Close()
			}
			return err == nil
		}, 10*time.Second, 50*time.Millisecond)
		return cmd
	}
	monitor := start()
	dir := t.TempDir()
	m := &monitorSession{dir: dir, profile: monitorProfile{Name: "personal"}, url: "http://" + api, http: &http.Client{Timeout: 10 * time.Second}, owner: bytes.Repeat([]byte{8}, monitorOwnerKeyBytes)}
	require.ErrorContains(t, m.call("/unlock", map[string]uint64{"generation": 0}), "401", "another secret cannot claim an empty Monitor")
	m.owner = owner
	require.NoError(t, m.call("/unlock", map[string]uint64{"generation": 0}))

	laptop := testSigner(t)
	laptopLine := authorizedLine(laptop)
	require.NoError(t, m.call("/policy/edits", map[string]any{"changes": []map[string]any{{"path": []string{"identities", "laptop"}, "value": map[string]any{"key": laptopLine, "accounts": map[string]any{}}}}}))
	deviceLine, err := ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
	require.NoError(t, err)
	require.ErrorIs(t, m.deviceRoutes(), errDeviceUnregistered)
	require.NoError(t, m.registerDevice())
	_, deviceName, err := m.device()
	require.NoError(t, err)
	identities := ownerIdentities(t, m)
	require.Equal(t, laptopLine, strings.TrimSpace(identities["laptop"].Key), "unrelated identities are preserved")
	require.False(t, identities["laptop"].Routes)
	require.True(t, identities[deviceName].Routes)
	require.NoError(t, m.deviceRoutes())
	generation := m.state.Generation
	require.NoError(t, m.registerDevice(), "a registered device is not added twice")
	require.NoError(t, m.ensureIdentity("sandbox-work", deviceLine, false), "a key Monitor already knows is not added twice")
	require.ErrorContains(t, m.ensureIdentity(deviceName, authorizedLine(testSigner(t)), false), "another key")
	require.ErrorContains(t, m.removeIdentity("laptop", deviceLine), "another key")
	require.Equal(t, generation, m.state.Generation)
	revoke := func(change map[string]any) {
		require.NoError(t, m.call("/policy/edits", map[string]any{"changes": []map[string]any{change}}))
	}
	revoke(map[string]any{"path": []string{"identities", deviceName, "routes"}, "value": false})
	generation = m.state.Generation
	require.ErrorContains(t, m.deviceRoutes(), deviceLine, "the owner can add the identity back from the message")
	require.ErrorContains(t, m.registerDevice(), "lost route access", "the CLI never grants routes back")
	revoke(map[string]any{"path": []string{"identities", deviceName}, "delete": true})
	generation = m.state.Generation
	require.ErrorContains(t, m.registerDevice(), "removed", "a removed device is not registered again")
	require.Equal(t, generation, m.state.Generation)

	ahead := &monitorSession{dir: t.TempDir(), profile: monitorProfile{Name: "personal", Generation: m.state.Generation + 5}, url: m.url, http: m.http, owner: owner}
	require.ErrorContains(t, ahead.call("/unlock", map[string]uint64{"generation": ahead.profile.Generation}), "older than")

	monitor.Process.Kill()
	monitor.Wait()
	start()
	restarted := &monitorSession{dir: dir, profile: m.profile, url: m.url, http: m.http, owner: owner}
	require.NoError(t, restarted.call("/unlock", map[string]uint64{"generation": m.profile.Generation}))
	require.Contains(t, restarted.state.Config.Identities, "laptop", "the encrypted policy survives a restart")
}

func freeAddress(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().String()
}

func testSigner(t *testing.T) ssh.Signer {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	return signer
}

func authorizedLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func assertNoError(t *testing.T, err error) bool {
	if err != nil {
		t.Error(err)
	}
	return err == nil
}

func ownerIdentities(t *testing.T, m *monitorSession) map[string]struct {
	Key    string `json:"key"`
	Routes bool   `json:"routes"`
} {
	req, err := http.NewRequest(http.MethodGet, m.url+"/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(m.owner))
	resp, err := m.http.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var view struct {
		Config struct {
			Identities map[string]struct {
				Key    string `json:"key"`
				Routes bool   `json:"routes"`
			} `json:"identities"`
		} `json:"config"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&view))
	return view.Config.Identities
}

func TestPrivateMonitorUsesLocalTemplateAndCachesOnlyVerifiedBytes(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	f := newMonitorCPFixture(t)
	client := newCPClient(cliConfig{ControlplaneURL: f.server.URL, APIKey: "admin_test"})
	scope := accountScope{ControlplaneURL: f.server.URL, UserID: "user_private"}
	path := filepath.Join(t.TempDir(), "tinfoil-config.yml")
	require.NoError(t, os.WriteFile(path, []byte(testMonitorTemplate), 0600))
	oldPath := monitorTemplatePath
	monitorTemplatePath = path
	t.Cleanup(func() { monitorTemplatePath = oldPath })
	// This address cannot serve a public template. The private checkout is the
	// independent source for verifying the returned measured config.
	require.NoError(t, provisionMonitor(client, scope, "personal", "http://127.0.0.1:1"))
	monitorTemplatePath = ""
	require.NoError(t, os.Remove(path))
	require.NoError(t, provisionMonitor(client, scope, "personal", "http://127.0.0.1:1"))
	f.mutate = func(row *containerView) { row.Config += "debug: true\n" }
	require.ErrorContains(t, provisionMonitor(client, scope, "personal", "http://127.0.0.1:1"), "measured config does not match")
}

func TestMonitorExplicitRevisionChangePreservesOwnerAndStateGeneration(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	f := newMonitorCPFixture(t)
	client := newCPClient(cliConfig{ControlplaneURL: f.server.URL, APIKey: "admin_test"})
	scope := accountScope{ControlplaneURL: f.server.URL, UserID: "user_private"}
	require.NoError(t, provisionMonitor(client, scope, "personal", f.server.URL))
	dir, err := monitorDir(scope, "personal")
	require.NoError(t, err)
	before, err := updateProfile(dir, func(p *monitorProfile) error { p.Generation = 42; return nil })
	require.NoError(t, err)
	f.exists = false
	f.template = "cpus: 2\n" + testMonitorTemplate
	path := filepath.Join(t.TempDir(), "tinfoil-config.yml")
	require.NoError(t, os.WriteFile(path, []byte(f.template), 0600))
	oldPath := monitorTemplatePath
	monitorTemplatePath, monitorTag = path, "v2"
	t.Cleanup(func() { monitorTemplatePath = oldPath })
	require.NoError(t, provisionMonitor(client, scope, "personal", "http://127.0.0.1:1"))
	var after monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileName), &after))
	require.Equal(t, []string{"v1", "v2"}, f.tags)
	require.Equal(t, f.digests[0], f.digests[1])
	require.Equal(t, []string{"", before.StorageID}, f.storageIDs)
	require.Equal(t, before.StorageID, after.StorageID)
	require.Equal(t, uint64(42), after.Generation)
	require.NotEqual(t, before.Source, after.Source)
}
