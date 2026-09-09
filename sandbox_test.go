package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

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

func TestPostEnrollmentSendsBothKeysWithThePermit(t *testing.T) {
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

	keys := &sandboxKeys{dir: "/keys", diskKey: "dGhlIGRpc2sga2V5", publicKey: "ssh-ed25519 AAAAC3Nz"}
	if err := postEnrollment(server.Client(), server.URL+sandboxEnrollPath, "the.permit.token", keys); err != nil {
		t.Fatalf("postEnrollment: %v", err)
	}
	if authorization != "Bearer the.permit.token" {
		t.Fatalf("Authorization = %q, want the permit as a bearer token", authorization)
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
			name:   "expired permit points at a restart",
			status: http.StatusForbidden,
			reply:  `{"error":"permit refused"}`,
			want:   "restart",
		},
		{
			name:   "a spent permit says so",
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

			keys := &sandboxKeys{dir: "/keys", diskKey: "dGhlIGRpc2sga2V5", publicKey: "ssh-ed25519 AAAAC3Nz"}
			err := postEnrollment(server.Client(), server.URL+sandboxEnrollPath, "the.permit.token", keys)
			if err == nil {
				t.Fatalf("postEnrollment accepted %d", tt.status)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestRenderSandboxNeverPrintsThePermit(t *testing.T) {
	box := sandboxView{ID: "my-sandbox", Domain: "otter.box2.tinfoil.sh", State: sandboxStateRunning, Permit: "the.permit.token"}
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			outputFormat = format
			t.Cleanup(func() { outputFormat = "table" })
			out := captureStdout(t, func() {
				if err := renderSandbox(box); err != nil {
					t.Fatalf("renderSandbox: %v", err)
				}
			})
			if strings.Contains(out, box.Permit) {
				t.Fatalf("output carries the permit: %q", out)
			}
			if !strings.Contains(out, box.ID) {
				t.Fatalf("output = %q, want it to name the sandbox", out)
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
