package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
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
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const loginRecordName = "login"

func dekRecordName(apiOrigin, userID string) string {
	return "dek-" + storageHash([]byte(apiOrigin + "\x00" + userID))[:32]
}

func writeCredential(name string, value any) error {
	return writeCredentialTo(auth.OSKeyring{}, name, value)
}

func writeCredentialTo(keyring auth.Keyring, name string, value any) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	slot := struct {
		Keyring bool            `json:"keyring"`
		Record  json.RawMessage `json:"record,omitempty"`
	}{Keyring: true}
	if err := keyring.Set("tinfoil-cli", name, string(data)); err != nil {
		slot.Record = data
	}
	return writeStorageJSON(filepath.Join(filepath.Dir(path), "credentials", name+".json"), slot, false)
}

func TestWhoamiIdentityAndCredentialSource(t *testing.T) {
	commandState := newCommandFixture()

	for _, source := range []string{"file", envAdminKey, envAPIKey} {
		for _, personal := range []bool{false, true} {
			t.Run(source+"/personal="+boolText(personal), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/api/auth/context" || r.Header.Get("Authorization") != "Bearer admin_identity_secret" {
						t.Errorf("unexpected identity request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if personal {
						io.WriteString(w, `{"context_type":"personal","organization":null,"user_id":"user_1"}`)
					} else {
						io.WriteString(w, `{"context_type":"organization","organization":{"id":"org_1"},"user_id":"user_1"}`)
					}
				}))
				defer server.Close()
				t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
				t.Setenv(envCPURL, server.URL)
				t.Setenv(envAdminKey, "")
				t.Setenv(envAPIKey, "tk_ignored")
				if source == "file" {
					if _, err := saveConfig(cliConfig{APIKey: "admin_identity_secret", ControlplaneURL: server.URL}); err != nil {
						t.Fatal(err)
					}
				} else {
					t.Setenv(source, "admin_identity_secret")
				}
				out, err := captureTestStdout(func() error { return commandState.whoamiCmd.RunE(commandState.whoamiCmd, nil) })
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{source, "user_1", "Effective login", "admin_id…cret"} {
					if !strings.Contains(string(out), want) {
						t.Fatalf("missing %q: %s", want, out)
					}
				}
				if strings.Contains(string(out), "admin_identity_secret") || strings.Contains(string(out), "Organization name") {
					t.Fatalf("unexpected identity output: %s", out)
				}
				if personal != strings.Contains(string(out), "Context: personal") {
					t.Fatalf("wrong context: %s", out)
				}
			})
		}
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestLoginReportsSavedAndEffectiveIdentity(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/context" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		id := "org_saved"
		if r.Header.Get("Authorization") == "Bearer admin_environment_secret" {
			id = "org_effective"
		}
		io.WriteString(w, `{"context_type":"organization","organization":{"id":"`+id+`","name":"Example"},"user_id":"user_1"}`)
	}))
	defer server.Close()
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_environment_secret")
	t.Setenv(envAPIKey, "")
	keyFlag := commandState.loginCmd.Flags().Lookup("api-key")
	oldValue, oldChanged := keyFlag.Value.String(), keyFlag.Changed
	t.Cleanup(func() { _ = keyFlag.Value.Set(oldValue); keyFlag.Changed = oldChanged })
	if err := commandState.loginCmd.Flags().Set("api-key", "admin_saved_secret"); err != nil {
		t.Fatal(err)
	}
	var stdout []byte
	warning, err := captureTestStderr(func() error {
		var err error
		stdout, err = captureTestStdout(func() error { return commandState.loginCmd.RunE(commandState.loginCmd, nil) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(stdout), "Effective login:")
	if len(parts) != 2 || !strings.Contains(parts[0], "org_saved") || !strings.Contains(parts[1], "org_effective") || strings.Contains(parts[1], "org_saved") {
		t.Fatalf("wrong saved/effective identity: %s", stdout)
	}
	if !strings.Contains(string(warning), "WARNING: environment overrides") {
		t.Fatalf("missing warning: %s", warning)
	}
	warning, err = captureTestStderr(func() error {
		_, err := captureTestStdout(func() error { return commandState.logoutCmd.RunE(commandState.logoutCmd, nil) })
		return err
	})
	if err != nil || !strings.Contains(string(warning), envAdminKey+" is still active") {
		t.Fatalf("logout warning=%s err=%v", warning, err)
	}
}

func TestIdentityRejectsInvalidAndUnauthorizedResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"context_type":"organization","organization":{"id":"org_1"}}`, `{"context_type":"organization","organization":null}`, `{"context_type":"personal","organization":{"id":"org_wrong"},"user_id":"user_1"}`, `unauthorized`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body == "unauthorized" {
					w.WriteHeader(http.StatusUnauthorized)
				}
				io.WriteString(w, body)
			}))
			defer server.Close()
			if _, err := authenticatedContext(cliConfig{ControlplaneURL: server.URL}); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestLoginInvalidEnvironmentDoesNotClaimEffectiveIdentity(t *testing.T) {
	commandState := newCommandFixture()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/context" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		if r.Header.Get("Authorization") != "Bearer admin_saved_secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"context_type":"personal","organization":null,"user_id":"user_saved"}`)
	}))
	defer server.Close()
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_invalid_environment")
	t.Setenv(envAPIKey, "")
	flag := commandState.loginCmd.Flags().Lookup("api-key")
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() { _ = flag.Value.Set(oldValue); flag.Changed = oldChanged })
	if err := commandState.loginCmd.Flags().Set("api-key", "admin_saved_secret"); err != nil {
		t.Fatal(err)
	}
	out, err := captureTestStdout(func() error { return commandState.loginCmd.RunE(commandState.loginCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "credentials saved, but effective environment login could not be verified") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(string(out), "Effective login:") || strings.Contains(string(out), "Logged in") || !strings.Contains(string(out), "user_saved") {
		t.Fatalf("false effective identity: %s", out)
	}
	t.Setenv(envAdminKey, "")
	cfg, _, err := loadConfig(testStreams())
	if err != nil || cfg.APIKey != "admin_saved_secret" {
		t.Fatal("verified saved credential was lost")
	}
}

// useTestClerk points this build's trusted Clerk and API targets at a test server.
func useTestClerk(t *testing.T, origin string) {
	t.Helper()
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envAdminKey, "")
	t.Setenv(envAPIKey, "")
	previous := [4]string{fixedAPIOrigin, clerkIssuer, clerkCLIClientID, clerkCLIAPIScope}
	fixedAPIOrigin, clerkIssuer, clerkCLIClientID, clerkCLIAPIScope = origin, origin, "fixture-client", "api:full"
	t.Cleanup(func() {
		fixedAPIOrigin, clerkIssuer, clerkCLIClientID, clerkCLIAPIScope = previous[0], previous[1], previous[2], previous[3]
	})
}

// flakyCredentials is an OS credential service that can go down and recover with its contents.
type flakyCredentials struct {
	mu    sync.Mutex
	store map[string]string
	down  bool
}

func (f *flakyCredentials) Get(_, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return "", errors.New("credential service unavailable")
	}
	secret, ok := f.store[user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return secret, nil
}

func (f *flakyCredentials) Set(_, user, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("credential service unavailable")
	}
	f.store[user] = secret
	return nil
}

func (f *flakyCredentials) Delete(_, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("credential service unavailable")
	}
	if _, ok := f.store[user]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.store, user)
	return nil
}

func useFlakyCredentials(t *testing.T) *flakyCredentials {
	t.Helper()
	service := &flakyCredentials{store: map[string]string{}}
	return service
}

// testAgent serves an in-process ssh-agent holding keys on a unix socket.
func testAgent(t *testing.T, keys ...ed25519.PrivateKey) agent.Agent {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	held := agent.NewKeyring()
	for _, key := range keys {
		require.NoError(t, held.Add(agent.AddedKey{PrivateKey: key}))
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				agent.ServeAgent(held, conn)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
	return held
}

func TestLogoutRemovesSyncedMaterialAndKeepsUserKeys(t *testing.T) {
	revoked := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST /oauth/token/revoke", r.Method+" "+r.URL.Path)
		require.NoError(t, r.ParseForm())
		revoked <- r.PostForm.Get("token")
		http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	useTestClerk(t, server.URL)
	service := useFlakyCredentials(t)
	accounts := testAccountsWithCredentials(service)
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "personal",
		AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, writeCredentialTo(service, loginRecordName, grant))
	client := accounts.client(testStreams(), cliConfig{ControlplaneURL: server.URL, login: grant})
	dek := &syncedDEK{Version: 1, APIOrigin: server.URL, UserID: "user_owner", DEKID: randomB64U(16), DEK: make(b64u, 32)}
	require.NoError(t, writeCredentialTo(service, dekRecordName(server.URL, "user_owner"), dek))
	// A DEK left by an earlier user's interrupted login commit, with no login record of its own.
	service.down = true
	require.NoError(t, writeCredentialTo(service, dekRecordName(server.URL, "user_earlier"), dek))
	service.down = false

	scope := accountScope{ControlplaneURL: server.URL, UserID: "user_owner"}
	sandboxDir, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111", "work")
	require.NoError(t, err)
	synced, ownSeed := testSeed(t), testSeed(t)
	exported, err := exportTMKIdentity(client, sandboxDir, synced)
	require.NoError(t, err)
	device := func(id, custody string) string {
		dir, err := resourceDir(scope, id, "monitor")
		require.NoError(t, err)
		require.NoError(t, writeStorageJSON(filepath.Join(dir, monitorProfileFile), monitorProfile{Custody: custody}, false))
		_, err = ensureSSHKey(filepath.Join(dir, monitorDeviceKeyName))
		require.NoError(t, err)
		return filepath.Join(dir, monitorDeviceKeyName)
	}
	tmkDevice, umkDevice := device("22222222-2222-4222-8222-222222222222", "tmk"), device("33333333-3333-4333-8333-333333333333", "umk")
	umkRecord, err := umkRecordPath(scope, "44444444-4444-4444-8444-444444444444")
	require.NoError(t, err)
	_, err = saveUMKRecord(testStreams(), umkRecord, newUMKRecord("sandbox", ed25519PublicKeyString(ownSeed)))
	require.NoError(t, err)
	userKey := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, ensureOwnerSSHKey(userKey, ownSeed))
	privateKey := func(path string) ed25519.PrivateKey {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		key, err := ssh.ParseRawPrivateKey(raw)
		require.NoError(t, err)
		return *key.(*ed25519.PrivateKey)
	}
	held := testAgent(t, privateKey(exported), privateKey(tmkDevice), privateKey(userKey))

	out := &strings.Builder{}
	streams := testStreams()
	streams.out = out
	require.NoError(t, accounts.clerkLogout(streams))
	require.Contains(t, out.String(), "Could not revoke", "revocation failure is reported but does not stop local cleanup")
	require.Equal(t, "refresh-1", <-revoked)
	gone, err := accounts.currentGrant(testStreams())
	require.NoError(t, err)
	require.Nil(t, gone)
	require.Empty(t, service.store, "logout removes the login and every synced DEK from the OS service")
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(exported), "..", "..", "..", "credentials", "*.json"))
	require.Empty(t, leftovers)
	require.NoFileExists(t, exported)
	require.NoFileExists(t, tmkDevice)
	require.FileExists(t, umkDevice, "UMK resources keep their local material")
	require.FileExists(t, umkRecord)
	require.FileExists(t, userKey)
	listed, err := held.List()
	require.NoError(t, err)
	require.Len(t, listed, 1, "only the user's own key stays in ssh-agent")
	require.Equal(t, mustSigner(t, userKey).PublicKey().Marshal(), listed[0].Marshal())

	// A command delayed past logout cannot recreate synced material.
	_, err = exportTMKIdentity(client, sandboxDir, synced)
	require.ErrorContains(t, err, "signed out")
	require.ErrorContains(t, whileSignedIn(client, func() error { _, err := ensureSSHKey(tmkDevice); return err }), "signed out")
	require.NoFileExists(t, exported)
	require.NoFileExists(t, tmkDevice)
}

func mustSigner(t *testing.T, path string) ssh.Signer {
	t.Helper()
	signer, err := loadSigner(path)
	require.NoError(t, err)
	return signer
}

func TestClerkCredentialsUseOnlyTheFixedAPIOrigin(t *testing.T) {
	requests := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		io.WriteString(w, `{"context_type":"personal","organization":null,"user_id":"user_owner"}`)
	}))
	defer other.Close()
	fixed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer access-1", r.Header.Get("Authorization"))
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer fixed.Close()
	useTestClerk(t, fixed.URL)
	t.Setenv(envCPURL, other.URL)
	require.NoError(t, writeCredential(loginRecordName, &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: fixed.URL, ClientID: "fixture-client",
		UserID: "user_owner", Account: "personal", AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}))
	cfg, err := requireAuth()
	require.NoError(t, err)
	require.Equal(t, fixed.URL, cfg.ControlplaneURL, "saved or environment URLs never retarget a Clerk login")
	_, err = authenticatedContext(cfg)
	require.ErrorContains(t, err, "refusing a controlplane redirect")
	require.Zero(t, requests, "the bearer token never follows a redirect")

	// An explicit admin key keeps its own configured target and never sees the Clerk token.
	t.Setenv(envAdminKey, "admin_automation")
	cfg, err = requireAuth()
	require.NoError(t, err)
	require.Nil(t, cfg.login)
	require.Equal(t, other.URL, cfg.ControlplaneURL)
}

func TestUnauthenticatedListDoesNotClaimAnEmptyAccount(t *testing.T) {
	commandState := newCommandFixture()

	useTestClerk(t, "https://api.example")
	for _, kind := range []string{"sandbox", "monitor"} {
		cmd := newManagedStatusCmd(testAuthedClient, commandState.outputOpts, kind)
		out, err := captureTestStdout(func() error { return cmd.RunE(cmd, nil) })
		require.NoError(t, err)
		require.Contains(t, string(out), "stored on this machine")
		require.Contains(t, string(out), "tinfoil login")
		_, err = captureTestStdout(func() error { return cmd.RunE(cmd, []string{"work"}) })
		require.ErrorIs(t, err, errNotLoggedIn)
	}
}

func TestLogoutRemovesSavedAdminKeyDespiteCredentialServiceOutage(t *testing.T) {
	commandState := newCommandFixture()

	useTestClerk(t, "https://api.example")
	service := useFlakyCredentials(t)
	accounts := testAccountsWithCredentials(service)
	commandState.logoutCmd = newLogoutCommand(accounts)
	path, err := saveConfig(cliConfig{ControlplaneURL: "https://api.example", APIKey: "admin_saved_secret"})
	require.NoError(t, err)
	require.NoError(t, writeCredentialTo(service, loginRecordName, &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: "https://api.example", ClientID: "fixture-client",
		UserID: "user_owner", Account: "personal", AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}))
	owner := ed25519PublicKeyString(testSeed(t))
	umk, err := umkRecordPath(accountScope{ControlplaneURL: "https://api.example", UserID: "user_owner"}, testContainerID)
	require.NoError(t, err)
	_, err = saveUMKRecord(testStreams(), umk, newUMKRecord("sandbox", owner))
	require.NoError(t, err)
	t.Setenv(envAPIKey, "admin_environment_secret")

	service.down = true
	var logoutErr error
	warning, err := captureTestStderr(func() error {
		_, logoutErr = captureTestStdout(func() error { return commandState.logoutCmd.RunE(commandState.logoutCmd, nil) })
		return nil
	})
	require.NoError(t, err)
	require.ErrorContains(t, logoutErr, "still holds a copy", "incomplete keyring cleanup is reported")
	require.NoFileExists(t, path, "the saved admin key is removed anyway")
	require.Contains(t, string(warning), envAPIKey+" is still active")
	require.FileExists(t, umk)

	service.down = false
	grant, err := accounts.currentGrant(testStreams())
	require.NoError(t, err)
	require.Nil(t, grant, "the login stays removed after the service recovers")
	require.Contains(t, service.store, loginRecordName)
	_, err = captureTestStdout(func() error { return commandState.logoutCmd.RunE(commandState.logoutCmd, nil) })
	require.NoError(t, err, "a later logout finishes the cleanup")
	require.Empty(t, service.store)
}
