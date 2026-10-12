package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
)

const testSandboxOwnerHash = "c422e7070cb1cb455b5de9afee0d975e303d0239c72030cd7414ab5c382d3ae8"

func TestSandboxCreateBindsSavedOwnerBeforeBoot(t *testing.T) {
	oldTag, oldVariables := sandboxTag, sandboxVariables
	sandboxTag = "v1"
	sandboxVariables = []string{"MODE=custom"}
	t.Cleanup(func() { sandboxTag, sandboxVariables = oldTag, oldVariables })
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envAdminKey, "admin_test")
	keys, err := ensureSandboxKeys("work")
	require.NoError(t, err)
	owner := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'B'}, sandboxDiskKeyBytes))
	require.NoError(t, os.WriteFile(filepath.Join(keys.dir, sandboxDiskKeyName), []byte(owner), 0600))
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "POST /api/containers", r.Method+" "+r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var request struct {
			Name      string            `json:"name"`
			Repo      string            `json:"repo"`
			Tag       string            `json:"tag"`
			Variables map[string]string `json:"variables"`
		}
		require.NoError(t, json.Unmarshal(body, &request))
		require.Equal(t, "work", request.Name)
		require.Equal(t, defaultSandboxRepo, request.Repo)
		require.Equal(t, "v1", request.Tag)
		require.Equal(t, map[string]string{"SANDBOX_OWNER_KEY_SHA256": testSandboxOwnerHash, "MODE": "custom"}, request.Variables)
		require.NotContains(t, string(body), owner)
		// Stop at provisioning so this test never needs an attestation provider.
		http.Error(w, `{"error":"provisioning unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv(envCPURL, server.URL)
	for range 2 {
		require.ErrorContains(t, sandboxCreateCmd.RunE(sandboxCreateCmd, []string{"work"}), "provisioning unavailable")
	}
	require.Equal(t, 2, requests)
	_, err = claimBoot("POST", "/api/containers/missing/deploy", "missing", nil)
	require.ErrorContains(t, err, "no disk key")
	require.NoError(t, os.Remove(keys.sshKeyPath))
	_, err = claimBoot("POST", "/api/containers/work/deploy", "work", nil)
	require.ErrorContains(t, err, "restore the sandbox login key")
	require.NoFileExists(t, keys.sshKeyPath)
	require.Equal(t, 2, requests, "missing credentials must fail before boot")
}

func TestSandboxSourceRequiresLocalOwnerAndReleaseTemplate(t *testing.T) {
	oldVariables := sandboxVariables
	sandboxVariables = []string{"MODE=custom"}
	t.Cleanup(func() { sandboxVariables = oldVariables })
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	keys, err := ensureSandboxKeys("work")
	require.NoError(t, err)
	owner := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'B'}, sandboxDiskKeyBytes))
	require.NoError(t, os.WriteFile(filepath.Join(keys.dir, sandboxDiskKeyName), []byte(owner), 0600))
	template := []byte("containers:\n  - name: workspace\n    env: [DOMAIN, 'SANDBOX_OWNER_KEY_SHA256=default-owner', 'MODE=default']\n")
	rendered, err := renderTemplateEnv(template, map[string]string{sandboxOwnerEnv: testSandboxOwnerHash, "MODE": "custom"})
	require.NoError(t, err)
	row := containerView{Repo: defaultSandboxRepo, CurrentTag: "v1", Domain: "work.example", ConfigName: "/" + sandboxConfigIdentity + "/" + storageHash(rendered), Config: string(rendered)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/containers/work-id":
			json.NewEncoder(w).Encode(row)
		case "/" + defaultSandboxRepo + "/v1/tinfoil-config.yml":
			w.Write(template)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newCPClient(cliConfig{ControlplaneURL: server.URL, APIKey: "admin_test"})
	box := sandboxView{ID: "work", ContainerID: "work-id", Domain: row.Domain}
	source, err := sandboxSource(client, box, server.URL)
	require.NoError(t, err)
	repo, revision, digest, err := verify.ParseReference(source)
	require.NoError(t, err)
	require.Equal(t, []string{"tinfoil/containers", storageHash(rendered), storageHash(rendered)}, []string{repo, revision, digest})
	sandboxVariables = nil
	_, err = sandboxSource(client, box, server.URL)
	require.ErrorContains(t, err, "--variable values")
	sandboxVariables = []string{"MODE=custom"}
	for _, config := range []string{
		strings.Replace(string(rendered), testSandboxOwnerHash, strings.Repeat("a", 64), 1),
		string(rendered) + "debug: true\n",
		strings.Replace(string(rendered), "custom", "untrusted", 1),
		string(template),
	} {
		row.Config = config
		_, err := sandboxSource(client, box, server.URL)
		require.ErrorContains(t, err, "owner key")
	}
}

func TestSandboxNameRejectsNamesThatCannotBeDirectories(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "plain name", raw: "my-sandbox", want: "my-sandbox", valid: true},
		{name: "surrounding space is trimmed", raw: "  my-sandbox\n", want: "my-sandbox", valid: true},
		{name: "underscores and digits", raw: "box_2", want: "box_2", valid: true},
		{name: "longest allowed", raw: strings.Repeat("a", 63), want: strings.Repeat("a", 63), valid: true},
		{name: "too long", raw: strings.Repeat("a", 64)},
		{name: "empty", raw: ""},
		{name: "leading dash", raw: "-box"},
		{name: "path separator", raw: "a/b"},
		{name: "parent directory", raw: ".."},
		{name: "traversal", raw: "../../.ssh"},
		{name: "dot", raw: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sandboxName(tt.raw)
			if tt.valid {
				if err != nil {
					t.Fatalf("sandboxName(%q) failed: %v", tt.raw, err)
				}
				if got != tt.want {
					t.Fatalf("sandboxName(%q) = %q, want %q", tt.raw, got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("sandboxName(%q) = %q, want an error", tt.raw, got)
			}
		})
	}
}

func TestEnsureSandboxKeysMakesBothKeysAndKeepsThem(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))

	keys, err := ensureSandboxKeys("my-sandbox")
	if err != nil {
		t.Fatalf("ensureSandboxKeys: %v", err)
	}

	info, err := os.Stat(keys.dir)
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("key dir mode = %o, want 700", perm)
	}
	if base := filepath.Base(keys.dir); base != "my-sandbox" {
		t.Fatalf("key dir = %q, want it named after the sandbox", keys.dir)
	}

	decoded, err := base64.StdEncoding.DecodeString(keys.diskKey)
	if err != nil {
		t.Fatalf("disk key is not base64: %v", err)
	}
	if len(decoded) != sandboxDiskKeyBytes {
		t.Fatalf("disk key is %d bytes, want %d", len(decoded), sandboxDiskKeyBytes)
	}
	for _, name := range []string{sandboxDiskKeyName, sandboxSSHKeyName} {
		info, err := os.Stat(filepath.Join(keys.dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s mode = %o, want 600", name, perm)
		}
	}

	public, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(keys.publicKey))
	if err != nil {
		t.Fatalf("public key line is not one authorized_keys entry: %v", err)
	}
	if public.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("public key type = %q, want %q", public.Type(), ssh.KeyAlgoED25519)
	}
	if len(rest) != 0 {
		t.Fatalf("public key line has trailing content %q", rest)
	}
	if fields := strings.Fields(keys.publicKey); len(fields) != 2 {
		t.Fatalf("public key line has %d fields, want a type and a key", len(fields))
	}

	again, err := ensureSandboxKeys("my-sandbox")
	if err != nil {
		t.Fatalf("second ensureSandboxKeys: %v", err)
	}
	if again.diskKey != keys.diskKey {
		t.Fatal("disk key changed on the second call")
	}
	if again.publicKey != keys.publicKey {
		t.Fatal("SSH key changed on the second call")
	}
}

func TestEnsureDiskKeyRefusesAKeyItCannotUse(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))

	dir, err := sandboxKeyDir("my-sandbox")
	if err != nil {
		t.Fatalf("sandboxKeyDir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, sandboxDiskKeyName)
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if err := os.WriteFile(path, []byte(short), 0o600); err != nil {
		t.Fatalf("write disk key: %v", err)
	}

	if _, err := ensureSandboxKeys("my-sandbox"); err == nil {
		t.Fatal("ensureSandboxKeys accepted a key the volume worker would refuse")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read disk key: %v", err)
	}
	if string(saved) != short {
		t.Fatalf("disk key was rewritten to %q; a workspace key must never be replaced", saved)
	}
}

func testSandboxKeys() *sandboxKeys {
	return &sandboxKeys{
		dir:       "/keys",
		diskKey:   base64.StdEncoding.EncodeToString([]byte("the disk key")),
		publicKey: "ssh-ed25519 AAAAC3Nz",
	}
}

func TestPostEnrollmentSendsOwnerWorkspaceAndLoginKeys(t *testing.T) {
	type enrollment struct {
		Key    string `json:"key"`
		Volume string `json:"volume"`
	}
	var got enrollment
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("body is not an enrollment: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	keys := testSandboxKeys()
	if err := postEnrollment(server.Client(), server.URL+sandboxEnrollPath, keys); err != nil {
		t.Fatalf("postEnrollment: %v", err)
	}
	if authorization != "" {
		t.Fatalf("unexpected Authorization header %q", authorization)
	}
	if got.Key != keys.publicKey {
		t.Fatalf("key = %q, want %q", got.Key, keys.publicKey)
	}
	if got.Volume != keys.diskKey {
		t.Fatalf("volume = %q, want %q", got.Volume, keys.diskKey)
	}
}

func TestPostEnrollmentExplainsWhatTheSandboxRefused(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reply  string
		want   string
	}{
		{
			name:   "workspace key refused names the key directory",
			status: http.StatusForbidden,
			reply:  `{"error":"workspace key refused"}`,
			want:   "/keys",
		},
		{
			name:   "wrong owner key requires restoring credentials",
			status: http.StatusForbidden,
			reply:  `{"error":"owner key refused"}`,
			want:   "restore",
		},
		{
			name:   "changed enrollment conflicts",
			status: http.StatusConflict,
			reply:  `{"error":"sandbox is already enrolled"}`,
			want:   "already has an owner",
		},
		{
			name:   "anything else carries the status",
			status: http.StatusBadGateway,
			reply:  "gateway is unhappy",
			want:   "502",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.reply)
			}))
			defer server.Close()

			keys := testSandboxKeys()
			err := postEnrollment(server.Client(), server.URL+sandboxEnrollPath, keys)
			if err == nil {
				t.Fatalf("postEnrollment accepted %d", tt.status)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	saved := os.Stdout
	os.Stdout = file
	defer func() {
		os.Stdout = saved
		file.Close()
	}()

	run()

	captured, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(captured)
}

func TestSandboxLifecycleUsesContainerIDs(t *testing.T) {
	for _, action := range []string{"start", "restart", "stop", "delete"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			t.Setenv(envAdminKey, "admin_test")
			_, err := ensureSandboxKeys("work")
			require.NoError(t, err)
			oldYes := sandboxYes
			sandboxYes = true
			t.Cleanup(func() { sandboxYes = oldYes })
			row := containerView{ID: "container-id", Name: "work", Repo: defaultSandboxRepo, Status: statusRunning}
			if action == "start" {
				row.Status = statusStopped
			}
			var mutations []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				route := r.Method + " " + r.URL.Path
				switch route {
				case "GET /api/containers":
					json.NewEncoder(w).Encode([]containerView{row})
				case "GET /api/containers/container-id":
					json.NewEncoder(w).Encode(row)
				case "POST /api/containers/container-id/deploy":
					mutations = append(mutations, "deploy")
					row.Status = statusRunning
					json.NewEncoder(w).Encode(row)
				case "POST /api/containers/container-id/stop":
					mutations = append(mutations, "stop")
					row.Status = statusStopped
					json.NewEncoder(w).Encode(row)
				case "DELETE /api/containers/container-id":
					mutations = append(mutations, "delete")
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s", route)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			t.Setenv(envCPURL, server.URL)
			switch action {
			case "start":
				_, err = startSandbox("work")
				require.ErrorContains(t, err, "reported no domain") // Stop before external attestation.
				require.Equal(t, []string{"deploy"}, mutations)
			case "restart":
				err = sandboxRestartCmd.RunE(sandboxRestartCmd, []string{"work"})
				require.ErrorContains(t, err, "reported no domain")
				require.Equal(t, []string{"stop", "deploy"}, mutations)
			case "stop":
				box, stopErr := stopSandbox("work")
				require.NoError(t, stopErr)
				require.Equal(t, "work", box.ID)
				require.Equal(t, statusStopped, box.State)
				require.Equal(t, []string{"stop"}, mutations)
			case "delete":
				require.NoError(t, sandboxDeleteCmd.RunE(sandboxDeleteCmd, []string{"work"}))
				require.Equal(t, []string{"delete"}, mutations)
				_, err = loadSandboxKeys("work")
				require.NoError(t, err, "deleting compute must retain local workspace keys")
			}
		})
	}
}
