package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	return seed
}

func ensureOwnerSSHKey(path string, seed []byte) error {
	_, err := ensureSSHIdentity(path, seed)
	return err
}

// keyStateServer is an in-memory controlplane key-state owner: whole-state writes
// by revision CAS under one DEK.
type keyStateServer struct {
	mu        sync.Mutex
	revision  uint64
	dekID     *string
	mk        *string
	dropReply int                   // drop the reply of this many committed writes
	interpose func(*keyStateServer) // runs once before the next write is checked
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
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "personal",
		AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, writeCredential(loginRecordName, grant))
	dek := make([]byte, 32)
	rand.Read(dek)
	dekID := randomB64U(16)
	require.NoError(t, writeCredential(dekRecordName(server.URL, grant.UserID), &syncedDEK{Version: 1, APIOrigin: server.URL, UserID: grant.UserID, DEKID: dekID, DEK: dek}))
	if keys != nil {
		sealed, err := sealMK(&mkPayload{Version: 1, Resources: []mkResource{}}, dek, mkContext{server.URL, grant.UserID, dekID})
		require.NoError(t, err)
		keys.revision, keys.dekID, keys.mk = 1, &dekID, &sealed
	}
	cfg, err := requireAuth()
	require.NoError(t, err)
	return newCPClient(cfg), accountScope{ControlplaneURL: server.URL, UserID: grant.UserID}, dek
}

func TestKeyBundleUpdatesMergeConflictsAndSurviveLostReplies(t *testing.T) {
	keys := &keyStateServer{}
	server := httptest.NewServer(keys)
	defer server.Close()
	cp, scope, dek := testLogin(t, server, keys)
	mk, err := newMKSession(cp, scope)
	require.NoError(t, err)
	bundle := mk.context

	// A concurrent client commits its own key first; the stale write reloads and keeps both.
	first, second := newResourceKey("sandbox"), newResourceKey("monitor")
	keys.interpose = func(*keyStateServer) {
		_, err := mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, second) })
		require.NoError(t, err)
	}
	_, err = mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, first) })
	require.NoError(t, err)
	payload := keys.payload(t, dek, bundle)
	require.Len(t, payload.Resources, 2)
	for _, want := range []mkResource{first, second} {
		got := findKey(payload, func(r *mkResource) bool { return r.KeyID == want.KeyID })
		require.NotNil(t, got)
		require.Equal(t, want.OwnerSeed, got.OwnerSeed)
		require.Equal(t, want.StorageKey, got.StorageKey)
	}
	require.Equal(t, uint64(3), keys.revision)

	// A reply lost after commit reloads, finds the change applied and writes nothing more.
	keys.dropReply = 1
	_, err = mk.update(t.Context(), func(p *mkPayload) error {
		*findKey(p, func(r *mkResource) bool { return r.KeyID == second.KeyID }).MinGeneration = 5
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, uint64(4), keys.revision, "the lost reply must not commit twice")

	// Generation checkpoints merge by maximum and never lower.
	raise := func(generation uint64) {
		_, err := mk.update(t.Context(), func(p *mkPayload) error {
			r := findKey(p, func(r *mkResource) bool { return r.KeyID == second.KeyID })
			*r.MinGeneration = max(*r.MinGeneration, generation)
			return nil
		})
		require.NoError(t, err)
	}
	raise(3)
	require.Equal(t, uint64(4), keys.revision, "an unchanged bundle is not rewritten")
	raise(7)
	require.Equal(t, uint64(7), *findKey(keys.payload(t, dek, bundle), func(r *mkResource) bool { return r.KeyID == second.KeyID }).MinGeneration)

	// The same key ID with different key material is never replaced.
	collision := newResourceKey("sandbox")
	collision.KeyID = first.KeyID
	_, err = mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, collision) })
	require.ErrorContains(t, err, "different key material")
	require.Equal(t, first.StorageKey, findKey(keys.payload(t, dek, bundle), func(r *mkResource) bool { return r.KeyID == first.KeyID }).StorageKey)

	// A different winning DEK stops the update without writing.
	revision := keys.revision
	other := randomB64U(16)
	keys.dekID = &other
	_, err = mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, newResourceKey("sandbox")) })
	require.ErrorIs(t, err, errStaleDEK)
	require.Equal(t, revision, keys.revision)
}

func TestResourceKeysBindOnceAndNeverRegenerate(t *testing.T) {
	keys := &keyStateServer{}
	server := httptest.NewServer(keys)
	defer server.Close()
	cp, scope, dek := testLogin(t, server, keys)
	mk, err := newMKSession(cp, scope)
	require.NoError(t, err)
	saved := newResourceKey("sandbox")
	_, err = mk.update(t.Context(), func(p *mkPayload) error { return addKey(p, saved) })
	require.NoError(t, err)
	instance, volume := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", OwnerKeyMode: "tmk", OwnerPublicKey: saved.OwnerPublicKey}
	binding := mkBinding{Account: "personal", ContainerID: row.ID, InstanceID: &instance, VolumeID: &volume}
	dir := t.TempDir()

	resolved, err := resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", binding, dir, true)
	require.NoError(t, err)
	require.Equal(t, []byte(saved.StorageKey), resolved.storageKey)
	require.Equal(t, []byte(saved.MonitorIdentitySeed), resolved.monitorIdentitySeed)
	require.Equal(t, saved.OwnerPublicKey, ownerKeyString(resolved.signer.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)))
	signature, err := resolved.signer.Sign(rand.Reader, []byte("owner request"))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(ed25519.NewKeyFromSeed(saved.OwnerSeed).Public().(ed25519.PublicKey), []byte("owner request"), signature.Blob), "the resolved signer signs with the saved owner key")
	resolved.close()
	bound := findKey(keys.payload(t, dek, mk.context), func(r *mkResource) bool { return r.KeyID == saved.KeyID }).Binding
	require.Equal(t, &binding, bound)

	for name, change := range map[string]func(*mkBinding){
		"volume":    func(b *mkBinding) { other := "44444444-4444-4444-8444-444444444444"; b.VolumeID = &other },
		"instance":  func(b *mkBinding) { other := "55555555-5555-4555-8555-555555555555"; b.InstanceID = &other },
		"account":   func(b *mkBinding) { b.Account = "org_other" },
		"container": func(b *mkBinding) { b.ContainerID = "66666666-6666-4666-8666-666666666666" },
	} {
		changed := binding
		change(&changed)
		_, err := resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", changed, dir, true)
		require.ErrorContains(t, err, "no longer matches", name)
	}
	revision := keys.revision
	row.OwnerPublicKey = ed25519PublicKeyString(testSeed(t))
	_, err = resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", binding, dir, true)
	require.ErrorContains(t, err, "has no sandbox key")
	row.OwnerPublicKey = saved.OwnerPublicKey
	_, err = resolveResourceKeys(t.Context(), cp, scope, row, "monitor", binding, dir, true)
	require.ErrorContains(t, err, "has no monitor key")
	require.Equal(t, revision, keys.revision, "missing keys are never manufactured")
}

func TestUMKKeysStayLocalAndAreGeneratedOnlyOnce(t *testing.T) {
	keys := &keyStateServer{}
	server := httptest.NewServer(keys)
	defer server.Close()
	cp, scope, _ := testLogin(t, server, nil)
	seed := testSeed(t)
	owner := ed25519PublicKeyString(seed)
	home := t.TempDir()
	t.Setenv("HOME", home)
	previousIdentity := attestSSHIdentity
	attestSSHIdentity = filepath.Join(home, "owner")
	t.Cleanup(func() { attestSSHIdentity = previousIdentity })
	require.NoError(t, ensureOwnerSSHKey(attestSSHIdentity, seed))

	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", OwnerKeyMode: "umk", OwnerPublicKey: owner}
	path, err := umkRecordPath(scope, row.ID)
	require.NoError(t, err)
	results := make(chan *umkRecord, 8)
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			saved, err := saveUMKRecord(path, newUMKRecord("sandbox", owner))
			require.NoError(t, err)
			results <- saved
		})
	}
	wait.Wait()
	close(results)
	winner := <-results
	for saved := range results {
		require.Equal(t, winner.StorageKey, saved.StorageKey, "concurrent creators adopt one saved key")
	}

	instance, volume := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	binding := mkBinding{Account: "personal", ContainerID: row.ID, InstanceID: &instance, VolumeID: &volume}
	resolved, err := resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", binding, t.TempDir(), true)
	require.NoError(t, err)
	require.Equal(t, []byte(winner.StorageKey), resolved.storageKey)
	require.Equal(t, attestSSHIdentity, resolved.identity)
	resolved.close()
	other := "44444444-4444-4444-8444-444444444444"
	changed := binding
	changed.VolumeID = &other
	_, err = resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", changed, t.TempDir(), true)
	require.ErrorContains(t, err, "no longer matches")

	// Without a local record, a UMK resource gets no secrets until non-use is proven.
	require.NoError(t, os.Remove(path))
	resolved, err = resolveResourceKeys(t.Context(), cp, scope, row, "sandbox", binding, t.TempDir(), true)
	require.NoError(t, err)
	require.Nil(t, resolved.storageKey)
	require.Nil(t, resolved.monitorIdentitySeed)
	require.NoError(t, resolved.generateUMKKeys("sandbox", owner, binding))
	require.Len(t, resolved.storageKey, 32)
	require.FileExists(t, path)
	resolved.close()
}

func TestEncryptedOwnerIdentityFallsBackToAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	previousStdin, previousIdentity := os.Stdin, attestSSHIdentity
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin, attestSSHIdentity = previousStdin, previousIdentity; stdin.Close() })
	seed := testSeed(t)
	private := ed25519.NewKeyFromSeed(seed)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("test password"))
	require.NoError(t, err)
	attestSSHIdentity = filepath.Join(home, "encrypted-owner")
	require.NoError(t, os.WriteFile(attestSSHIdentity, pem.EncodeToMemory(block), 0600))
	socket := filepath.Join(home, "agent.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: private}))
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- agent.ServeAgent(keyring, conn)
	}()
	signer, path, closeSigner, err := userSigner(ed25519PublicKeyString(seed), home)
	require.NoError(t, err)
	defer closeSigner()
	require.Equal(t, filepath.Join(home, "owner.pub"), path)
	message := []byte("prove the agent can sign without an interactive prompt")
	signature, err := signer.Sign(nil, message)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(message, signature))
	closeSigner()
	require.ErrorIs(t, <-done, io.EOF)
}

func TestConcurrentSSHIdentityCreationPreservesWinner(t *testing.T) {
	for _, seed := range [][]byte{nil, testSeed(t)} {
		path := filepath.Join(t.TempDir(), "identity")
		results := make(chan string, 16)
		var wait sync.WaitGroup
		for range 16 {
			wait.Go(func() {
				signer, err := ensureSSHIdentity(path, seed)
				require.NoError(t, err)
				results <- authorizedLine(signer)
			})
		}
		wait.Wait()
		close(results)
		first := <-results
		for line := range results {
			require.Equal(t, first, line, "concurrent creators returned different keys")
		}
		require.ErrorContains(t, ensureOwnerSSHKey(path, testSeed(t)), "does not match")
	}
}

func TestCredentialsUseOnlyResourcePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: monitorRepo}
	data, err := json.Marshal(scope)
	require.NoError(t, err)
	require.NoError(t, writeStorageJSON(filepath.Join(home, "sandboxes", row.Name, "monitor.json"), map[string]any{"scope": scope, "monitor": "personal"}, false))
	require.NoError(t, writeStorageJSON(filepath.Join(home, "monitors", storageHash(data), row.Name, monitorProfileFile), monitorProfile{ContainerID: row.ID, Generation: 7}, false))
	got, err := monitorRecord(scope, &workloadTarget{containerView: row})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "resources", "user-owner-"+storageHash(data), "work-"+row.ID), got)
}

func savedResource(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileFile), monitorProfile{Generation: 7}, true))
}

func requireSavedResource(t *testing.T, dir string) {
	t.Helper()
	var profile monitorProfile
	require.NoError(t, readStorageJSON(filepath.Join(dir, monitorProfileFile), &profile))
	require.Equal(t, uint64(7), profile.Generation)
}

func TestAccountDirectoriesUseAuthenticatedDisplayNames(t *testing.T) {
	for _, test := range []struct {
		name, response, prefix, orgID string
	}{
		{"organization", `{"context_type":"organization","organization":{"id":"org_1","name":"Acme Labs"},"user_id":"user_1"}`, "org-acme-labs-", "org_1"},
		{"personal", `{"context_type":"personal","organization":null,"user_id":"user_1","user_name":"Ada Lovelace"}`, "user-ada-lovelace-", ""},
		{"older API", `{"context_type":"personal","organization":null,"user_id":"user_1"}`, "user-user_1-", ""},
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
			scope, _, err := currentScope()
			require.NoError(t, err)
			row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo}
			dir, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			data, err := json.Marshal(accountScope{ControlplaneURL: server.URL, OrgID: test.orgID, UserID: "user_1"})
			require.NoError(t, err)
			require.Equal(t, test.prefix+storageHash(data), filepath.Base(filepath.Dir(dir)), "display names must not change the deployed scope hash")
			savedResource(t, dir)
			scope.OrgName, scope.UserName, row.Name = "", "", ""
			got, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, dir, got, "lookup must not need either display name")
		})
	}
}

func TestAccountDirectoryLabelsAreSafeAndBounded(t *testing.T) {
	for _, name := range []string{"", "../../Acme / Labs\\team", strings.Repeat("company", 100), "会社"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example:8443", OrgID: "org_1", UserID: "owner", OrgName: name}
			dir, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111", "work")
			require.NoError(t, err)
			accountDir := filepath.Dir(dir)
			require.Equal(t, filepath.Join(home, "resources"), filepath.Dir(accountDir))
			require.LessOrEqual(t, len(filepath.Base(accountDir)), 255)
			require.NotContains(t, filepath.Base(accountDir), "\\")
			require.True(t, strings.HasPrefix(filepath.Base(accountDir), "org-"))
			if name == "" {
				require.True(t, strings.HasPrefix(filepath.Base(accountDir), "org-org_1-"))
			}
			savedResource(t, dir)
		})
	}
}

func TestResourceDirectoriesSurviveRenameAndSeparateRecreatedResources(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", OrgID: "org", UserID: "owner", OrgName: "Acme"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "my-work"}
	dir, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, row.Name+"-"+row.ID, filepath.Base(dir))
	require.True(t, strings.HasPrefix(filepath.Base(filepath.Dir(dir)), "org-acme-"))
	savedResource(t, dir)

	row.Name, scope.OrgName = "renamed-work", "Renamed Acme"
	renamed, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, renamed, "installed SSH identity paths must stay valid")
	requireSavedResource(t, renamed)
	row.Name, scope.OrgName = "", ""
	unnamed, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, unnamed, "resource and account names are optional for lookup")
	row.Name = "renamed-work"
	scope.OrgName = "Acme"

	for _, otherScope := range []accountScope{
		{ControlplaneURL: "https://other.example", OrgID: scope.OrgID, UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL + "/other", OrgID: scope.OrgID, UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL, OrgID: "other", UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL, OrgID: scope.OrgID, UserID: "other", OrgName: scope.OrgName},
	} {
		other, err := resourceDir(otherScope, row.ID, row.Name)
		require.NoError(t, err)
		require.NotEqual(t, filepath.Dir(dir), filepath.Dir(other))
		require.NoDirExists(t, other)
	}

	row.Name, row.ID = "my-work", "22222222-2222-4222-8222-222222222222"
	recreated, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(filepath.Dir(dir), row.Name+"-"+row.ID), recreated)
	require.NoDirExists(t, recreated, "reusing a name must not reuse credentials")
}

func TestResourceDirectoriesWithoutUsableName(t *testing.T) {
	for _, test := range []struct {
		name, label     string
		existingAccount bool
	}{
		{"new account", "../work", false},
		{"existing account", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
			hash := storageHash([]byte(`{"controlplane_url":"https://cp.example","user_id":"owner"}`))
			accountDir := filepath.Join(home, "resources", "user-owner-"+hash)
			if test.existingAccount {
				accountDir = filepath.Join(home, "resources", "saved-label-"+hash)
				require.NoError(t, os.MkdirAll(accountDir, 0700))
			}
			row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: test.label}
			dir, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, filepath.Join(accountDir, row.ID), dir)
			savedResource(t, dir)
			row.Name = "readable-name"
			got, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, dir, got, "a later usable name must preserve the existing credential path")
			requireSavedResource(t, got)
		})
	}
}

func TestExistingResourcePathsRemainUsable(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", OrgID: "org", UserID: "owner", OrgName: "Acme"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work"}
	named, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	// Resources saved without display labels keep their original hash and path.
	hash := storageHash([]byte(`{"controlplane_url":"https://cp.example","org_id":"org","user_id":"owner"}`))
	dir := filepath.Join(home, "resources", hash, row.ID)
	savedResource(t, dir)
	got, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, got)
	requireSavedResource(t, got)
	require.NoDirExists(t, filepath.Dir(named))
}

func TestResourceDirectoriesRejectAmbiguity(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo}
	dir, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	savedResource(t, dir)
	for _, name := range []string{row.ID, "old-name-" + row.ID} {
		other := filepath.Join(filepath.Dir(dir), name)
		require.NoError(t, os.Mkdir(other, 0700))
		_, err := resourceDir(scope, row.ID, row.Name)
		require.ErrorContains(t, err, "multiple credential directories")
		require.NoError(t, os.Remove(other))
	}
	data, err := json.Marshal(scope)
	require.NoError(t, err)
	accountDir := filepath.Dir(dir)
	for _, name := range []string{storageHash(data), "other-label-" + storageHash(data)} {
		other := filepath.Join(filepath.Dir(accountDir), name)
		require.NoError(t, os.Mkdir(other, 0700))
		_, err := resourceDir(scope, row.ID, row.Name)
		require.ErrorContains(t, err, "multiple credential directories")
		_, err = umkRecordPath(scope, row.ID)
		require.ErrorContains(t, err, "multiple credential directories")
		require.NoError(t, os.Remove(other))
	}
	requireSavedResource(t, dir)
}
