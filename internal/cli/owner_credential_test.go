package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"golang.org/x/crypto/ssh"
)

type keyState = controlplane.KeyState
type keyStateWrite = controlplane.KeyStateWrite

const keyStatePath = controlplane.KeyStatePath

func whileSignedIn(cp *cpClient, write func() error) error {
	service, err := cp.auth()
	if err != nil {
		return err
	}
	return service.WhileSignedIn(cp.login, write)
}

func fixtureResourceDirectory(config string, scope accountScope, id, name string) string {
	data, _ := json.Marshal(scope)
	label := "user-" + scope.UserID
	if scope.OrgID != "" {
		label = "org-" + scope.OrgID
	}
	return filepath.Join(filepath.Dir(config), "resources", label+"-"+storageHash(data), name+"-"+id)
}

func resourceDir(scope accountScope, id, name string) (string, error) {
	config, err := configPath()
	return fixtureResourceDirectory(config, scope, id, name), err
}

func umkRecordPath(scope accountScope, id string) (string, error) {
	dir, err := resourceDir(scope, id, "fixture")
	return filepath.Join(filepath.Dir(dir), "umk-"+storageHash([]byte(id))[:32]+".json"), err
}

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	return seed
}
func ownerKeyString(public ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(public)
}
func ensureOwnerSSHKey(path string, seed []byte) error {
	_, err := ensureSSHIdentity(path, seed)
	return err
}
func ensureSSHIdentity(path string, seed []byte) (ssh.Signer, error) {
	if seed == nil {
		seed = make([]byte, ed25519.SeedSize)
		rand.Read(seed)
	}
	private := ed25519.NewKeyFromSeed(seed)
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(private)
}
func ensureSSHKey(path string) (string, error) {
	signer, err := ensureSSHIdentity(path, nil)
	if err != nil {
		return "", err
	}
	return authorizedLine(signer), nil
}
func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}
func exportTMKIdentity(cp *cpClient, dir string, seed []byte) (string, error) {
	path := filepath.Join(dir, tmkOwnerKeyName)
	return path, whileSignedIn(cp, func() error {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		return ensureOwnerSSHKey(path, seed)
	})
}
func newUMKRecord(kind, owner string) map[string]any {
	return map[string]any{"version": 1, "kind": kind, "owner_public_key": owner, "storage_key": b64u(make([]byte, 32)), "monitor_identity_seed": b64u(make([]byte, 32)), "binding": nil}
}
func saveUMKRecord(path string, record map[string]any) (map[string]any, error) {
	return record, writeStorageJSON(path, record, true)
}
func measuredOwner(value string) (ssh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(value[len("ed25519:"):])
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(ed25519.PublicKey(raw))
}

func findKey(p *mkPayload, match func(*mkResource) bool) *mkResource {
	for i := range p.Resources {
		if match(&p.Resources[i]) {
			return &p.Resources[i]
		}
	}
	return nil
}

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + ".sandbox.invalid"
}

func monitorJump(sandbox, host string, port int, dir string, hostKey ssh.PublicKey, domain string) *sshProfile {
	return &sshProfile{name: sandbox + monitorJumpSuffix, hostName: host, port: port, user: monitorSSHUser, identityFile: filepath.Join(dir, monitorDeviceKeyName), hostKey: hostKey, hostKeyAlias: domain, noAgent: true}
}

// keyStateServer is an in-memory controlplane key-state owner: whole-state writes
// by revision CAS under one DEK.
type keyStateServer struct {
	mu        sync.Mutex
	revision  uint64
	dekID     *string
	mk        *string
	dropReply int
	interpose func(*keyStateServer)
}

func (s *keyStateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	switch {
	case r.Method == "GET" && r.URL.Path == keyStatePath:
		state := keyState{Revision: s.revision, DEKID: s.dekID, EncryptedMK: s.mk, Recovery: json.RawMessage("[]")}
		s.mu.Unlock()
		json.NewEncoder(w).Encode(state)
		return
	case r.Method == "PUT" && r.URL.Path == keyStatePath:
	default:
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if interpose := s.interpose; interpose != nil {
		s.interpose = nil
		s.mu.Unlock()
		interpose(s)
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var write keyStateWrite
	if err := decoder.Decode(&write); err != nil {
		http.Error(w, `{"error":"invalid"}`, 400)
		return
	}
	if write.ExpectedRevision != s.revision || s.dekID == nil || write.DEKID != *s.dekID {
		w.WriteHeader(409)
		io.WriteString(w, `{"error":"stale_revision","code":"CONFLICT"}`)
		return
	}
	s.mk = &write.EncryptedMK
	s.revision++
	if s.dropReply > 0 {
		s.dropReply--
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"revision": s.revision})
}
func (s *keyStateServer) payload(t *testing.T, dek []byte, c mkContext) *mkPayload {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := openMK(*s.mk, dek, c)
	require.NoError(t, err)
	return payload
}

// testLogin installs a synced Clerk login for user_owner against server.
func testLogin(t *testing.T, server *httptest.Server, keys *keyStateServer) (*cpClient, accountScope, []byte) {
	t.Helper()
	useTestClerk(t, server.URL)
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "personal", AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, writeCredential(loginRecordName, grant))
	dek := make([]byte, 32)
	rand.Read(dek)
	dekID := randomB64U(16)
	require.NoError(t, writeCredential(dekRecordName(server.URL, grant.UserID), &syncedDEK{Version: 1, APIOrigin: server.URL, UserID: grant.UserID, DEKID: dekID, DEK: dek}))
	if keys != nil {
		sealed, err := sealMK(&mkPayload{Version: 1, Resources: []mkResource{}}, dek, mkContext{APIOrigin: server.URL, UserID: grant.UserID, DEKID: dekID})
		require.NoError(t, err)
		keys.revision, keys.dekID, keys.mk = 1, &dekID, &sealed
	}
	cfg, err := requireAuth()
	require.NoError(t, err)
	return testCPClient(cfg), accountScope{ControlplaneURL: server.URL, UserID: grant.UserID}, dek
}

func TestAccountDirectoriesUseAuthenticatedDisplayNames(t *testing.T) {
	for _, test := range []struct{ name, response, orgID, orgName, userName string }{
		{"organization", `{"context_type":"organization","organization":{"id":"org_1","name":"Acme Labs"},"user_id":"user_1"}`, "org_1", "Acme Labs", ""},
		{"personal", `{"context_type":"personal","organization":null,"user_id":"user_1","user_name":"Ada Lovelace"}`, "", "", "Ada Lovelace"},
		{"older API", `{"context_type":"personal","organization":null,"user_id":"user_1"}`, "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/auth/context" {
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				io.WriteString(w, test.response)
			}))
			defer server.Close()
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			t.Setenv(envCPURL, server.URL)
			t.Setenv(envAdminKey, "admin_test")
			scope, _, err := testScopeClient(testStreams())
			require.NoError(t, err)
			require.Equal(t, accountScope{ControlplaneURL: server.URL, OrgID: test.orgID, UserID: "user_1", OrgName: test.orgName, UserName: test.userName}, scope)
		})
	}
}
