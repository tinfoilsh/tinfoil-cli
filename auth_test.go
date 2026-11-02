package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestWhoamiIdentityAndCredentialSource(t *testing.T) {
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
				out, err := captureTestStdout(func() error { return whoamiCmd.RunE(whoamiCmd, nil) })
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
	keyFlag := loginCmd.Flags().Lookup("api-key")
	oldValue, oldChanged := keyFlag.Value.String(), keyFlag.Changed
	t.Cleanup(func() { _ = keyFlag.Value.Set(oldValue); keyFlag.Changed = oldChanged })
	if err := loginCmd.Flags().Set("api-key", "admin_saved_secret"); err != nil {
		t.Fatal(err)
	}
	var stdout []byte
	warning, err := captureTestStderr(func() error {
		var err error
		stdout, err = captureTestStdout(func() error { return loginCmd.RunE(loginCmd, nil) })
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
		_, err := captureTestStdout(func() error { return logoutCmd.RunE(logoutCmd, nil) })
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
	flag := loginCmd.Flags().Lookup("api-key")
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() { _ = flag.Value.Set(oldValue); flag.Changed = oldChanged })
	if err := loginCmd.Flags().Set("api-key", "admin_saved_secret"); err != nil {
		t.Fatal(err)
	}
	out, err := captureTestStdout(func() error { return loginCmd.RunE(loginCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "credentials saved, but effective environment login could not be verified") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(string(out), "Effective login:") || strings.Contains(string(out), "Logged in") || !strings.Contains(string(out), "user_saved") {
		t.Fatalf("false effective identity: %s", out)
	}
	t.Setenv(envAdminKey, "")
	cfg, _, err := loadConfig()
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
	onSet func(user string)
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
	if f.onSet != nil {
		f.onSet(user)
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
	previous := osCredentials
	osCredentials = service
	t.Cleanup(func() { osCredentials = previous })
	return service
}

func TestCredentialStoreSurvivesServiceOutagesWithoutResurrection(t *testing.T) {
	useTestClerk(t, "https://api.example")
	service := useFlakyCredentials(t)
	type record struct{ Token string }
	read := func() (string, error) {
		var got record
		found, err := readCredential(loginRecordName, &got)
		if !found {
			return "", err
		}
		return got.Token, err
	}
	slot, err := credentialFile(loginRecordName)
	require.NoError(t, err)

	service.onSet = func(user string) {
		var selector credentialSlot
		require.NoError(t, readStorageJSON(slot, &selector), "the selector exists before the service holds a copy")
		require.True(t, selector.Keyring)
	}
	require.NoError(t, writeCredential(loginRecordName, record{"first"}))
	service.onSet = nil
	data, err := os.ReadFile(slot)
	require.NoError(t, err)
	require.NotContains(t, string(data), "first", "the secret lives only in the OS service")
	token, err := read()
	require.NoError(t, err)
	require.Equal(t, "first", token)

	service.down = true
	_, err = read()
	require.ErrorContains(t, err, "unavailable", "an outage is an error, never an older or empty record")
	// A rotation during the outage falls back to the file, which then wins over the older service copy.
	require.NoError(t, writeCredential(loginRecordName, record{"rotated"}))
	service.down = false
	require.Contains(t, service.store[loginRecordName], "first")
	token, err = read()
	require.NoError(t, err)
	require.Equal(t, "rotated", token)
	info, err := os.Stat(slot)
	require.NoError(t, err)
	require.EqualValues(t, 0o600, info.Mode().Perm())
	dir, err := os.Stat(filepath.Dir(slot))
	require.NoError(t, err)
	require.EqualValues(t, 0o700, dir.Mode().Perm())

	require.NoError(t, writeCredential(loginRecordName, record{"third"}))
	data, err = os.ReadFile(slot)
	require.NoError(t, err)
	require.NotContains(t, string(data), "rotated", "a recovered service takes the record back out of the file")
	token, err = read()
	require.NoError(t, err)
	require.Equal(t, "third", token)

	// A deletion during an outage fails visibly and stays deleted after recovery.
	service.down = true
	require.ErrorContains(t, deleteCredential(loginRecordName), "still holds a copy")
	token, err = read()
	require.NoError(t, err)
	require.Empty(t, token)
	service.down = false
	token, err = read()
	require.NoError(t, err)
	require.Empty(t, token, "a recovered service must not resurrect a deleted record")
	require.Contains(t, service.store, loginRecordName)
	require.NoError(t, deleteCredential(loginRecordName))
	require.NotContains(t, service.store, loginRecordName)
	require.NoFileExists(t, slot)
}

// fakeClerk serves Clerk's OAuth endpoints and the resource API for one user.
type fakeClerk struct {
	beforeKeys func()
	mu         sync.Mutex
	codeErr    string
	user       string
	account    string
	issued     int
	forms      []url.Values
	refreshErr string
	keys       *keyStateServer
}

func (f *fakeClerk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + r.URL.Path {
	case "POST /oauth/token":
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.forms = append(f.forms, r.PostForm)
		if failure := map[string]string{"refresh_token": f.refreshErr, "authorization_code": f.codeErr}[r.PostForm.Get("grant_type")]; failure != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": failure})
			return
		}
		f.issued++
		json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("access-%d", f.issued), "refresh_token": fmt.Sprintf("refresh-%d", f.issued),
			"token_type": "Bearer", "expires_in": 3600, "scope": "openid offline_access user:org:read api:full"})
	case "POST /oauth/token/revoke":
		r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		f.mu.Unlock()
		http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
	case "GET /oauth/userinfo":
		f.mu.Lock()
		defer f.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer access-") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identity := map[string]string{"sub": f.user, "user_id": f.user}
		if f.account != "personal" {
			identity["org_id"] = f.account
		}
		json.NewEncoder(w).Encode(identity)
	case "GET /api/auth/context":
		f.mu.Lock()
		defer f.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer access-") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.account == "personal" {
			json.NewEncoder(w).Encode(map[string]any{"context_type": "personal", "organization": nil, "user_id": f.user})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"context_type": "organization", "organization": map[string]string{"id": f.account}, "user_id": f.user})
	default:
		if f.keys != nil {
			f.mu.Lock()
			hook := f.beforeKeys
			f.beforeKeys = nil
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			f.keys.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (f *fakeClerk) refreshes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, form := range f.forms {
		if form.Get("grant_type") == "refresh_token" {
			count++
		}
	}
	return count
}

func TestClerkIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		reply   string
		account string
	}{
		{"personal", 200, `{"sub":"user_owner","user_id":"user_owner"}`, "personal"},
		{"organization", 200, `{"sub":"user_owner","org_id":"org_b"}`, "org_b"},
		{"null organization", 200, `{"sub":"user_owner","org_id":null}`, "personal"},
		{"rejected token", 401, `{"error":"invalid_token"}`, ""},
		{"Clerk unavailable", 503, `{}`, ""},
		{"missing subject", 200, `{"user_id":"user_owner"}`, ""},
		{"invalid subject", 200, `{"sub":"not-a-user"}`, ""},
		{"conflicting subjects", 200, `{"sub":"user_owner","user_id":"user_other"}`, ""},
		{"invalid organization", 200, `{"sub":"user_owner","org_id":"not-an-org"}`, ""},
		{"personal is not an organization ID", 200, `{"sub":"user_owner","org_id":"personal"}`, ""},
		{"malformed organization", 200, `{"sub":"user_owner","org_id":{}}`, ""},
		{"malformed JSON", 200, `{"sub":`, ""},
		{"null response", 200, `null`, ""},
		{"trailing JSON", 200, `{"sub":"user_owner"}{}`, ""},
		{"oversized response", 200, strings.Repeat("x", maxOAuthReplyBytes+1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET /oauth/userinfo", r.Method+" "+r.URL.Path)
				require.Empty(t, r.URL.RawQuery)
				require.Equal(t, "Bearer access-1", r.Header.Get("Authorization"))
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.reply)
			}))
			defer server.Close()
			useTestClerk(t, server.URL)
			user, account, err := clerkIdentity(t.Context(), "access-1")
			if tc.account == "" {
				require.Error(t, err)
				require.Empty(t, user)
				require.Empty(t, account)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "user_owner", user)
			require.Equal(t, tc.account, account)
		})
	}
}

func TestClerkIdentityDoesNotFollowRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Clerk identity requests must not follow redirects")
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	useTestClerk(t, server.URL)
	_, _, err := clerkIdentity(t.Context(), "access-1")
	require.ErrorContains(t, err, "Clerk /oauth/userinfo: 307")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err = clerkIdentity(ctx, "access-1")
	require.ErrorIs(t, err, context.Canceled)
}

func TestClerkIdentityFailurePreservesCredentials(t *testing.T) {
	clerk := &fakeClerk{user: "user_owner", account: "personal"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/userinfo" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"invalid_token"}`)
			return
		}
		clerk.ServeHTTP(w, r)
	}))
	defer server.Close()
	useTestClerk(t, server.URL)
	previous := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: clerkIssuer, ClientID: clerkCLIClientID,
		UserID: "user_owner", Account: "personal", AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	require.NoError(t, commitLogin(t.Context(), previous))
	scopes, err := clerkScopes()
	require.NoError(t, err)
	ceremony := &loginCeremony{ctx: t.Context(), scopes: scopes, verifier: randomB64U(32)}
	_, err = ceremony.redeem("code")
	require.ErrorContains(t, err, "checking the new login: Clerk /oauth/userinfo: 401")
	saved, err := currentGrant()
	require.NoError(t, err)
	require.Equal(t, previous, saved)
	_, err = previous.accessToken(t.Context())
	require.ErrorContains(t, err, "checking the renewed login: Clerk /oauth/userinfo: 401")
	saved, err = currentGrant()
	require.NoError(t, err)
	require.Equal(t, previous, saved)
}

func TestTokenRenewalIsSerializedAndKeepsTheGrantedAccount(t *testing.T) {
	clerk := &fakeClerk{user: "user_owner", account: "org_b"}
	server := httptest.NewServer(clerk)
	defer server.Close()
	useTestClerk(t, server.URL)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token renewal must not contact controlplane")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer api.Close()
	fixedAPIOrigin = api.URL
	expired := clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "org_b",
		AccessToken: "stale", RefreshToken: "refresh-0", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	require.NoError(t, writeCredential(loginRecordName, &expired))

	// Concurrent requests sharing one login, and separate commands with their own copies, rotate once.
	tokens := make(chan string, 8)
	var wait sync.WaitGroup
	shared := expired
	for i := range 8 {
		grant := &shared
		if i%2 == 1 {
			copied := expired
			grant = &copied
		}
		wait.Go(func() {
			token, err := grant.accessToken(t.Context())
			require.NoError(t, err)
			tokens <- token
		})
	}
	wait.Wait()
	close(tokens)
	for token := range tokens {
		require.Equal(t, "access-1", token)
	}
	require.Equal(t, 1, clerk.refreshes())
	require.Equal(t, "refresh-0", clerk.forms[0].Get("refresh_token"))
	require.Equal(t, "fixture-client", clerk.forms[0].Get("client_id"))
	require.Equal(t, api.URL, clerk.forms[0].Get("resource"))
	current, err := currentGrant()
	require.NoError(t, err)
	require.Equal(t, "refresh-1", current.RefreshToken)

	// A renewal that comes back for another account is refused and not saved.
	current.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	require.NoError(t, writeCredential(loginRecordName, current))
	for _, identity := range [][2]string{{"user_owner", "personal"}, {"user_owner", "org_other"}, {"user_other", "org_b"}} {
		clerk.user, clerk.account = identity[0], identity[1]
		_, err = current.accessToken(t.Context())
		require.ErrorContains(t, err, "different account")
		saved, err := currentGrant()
		require.NoError(t, err)
		require.Equal(t, current, saved)
	}
	clerk.user = "user_owner"

	clerk.account, clerk.refreshErr = "org_b", "invalid_grant"
	_, err = current.accessToken(t.Context())
	require.ErrorContains(t, err, "run `tinfoil login`")

	// After logout, a command still holding the old grant cannot use, renew or recreate it.
	clerk.refreshErr = ""
	fresh := *current
	fresh.ExpiresAt = time.Now().Add(time.Hour).Unix()
	require.NoError(t, writeCredential(loginRecordName, &fresh))
	token, err := fresh.accessToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, fresh.AccessToken, token)
	require.NoError(t, clerkLogout(io.Discard))
	_, err = fresh.accessToken(t.Context())
	require.ErrorContains(t, err, "login has ended", "a cached token is not admitted after logout")
	_, err = current.accessToken(t.Context())
	require.ErrorContains(t, err, "login has ended")
	gone, err := currentGrant()
	require.NoError(t, err)
	require.Nil(t, gone)
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
	clerk := &fakeClerk{user: "user_owner", account: "personal"}
	server := httptest.NewServer(clerk)
	defer server.Close()
	useTestClerk(t, server.URL)
	service := useFlakyCredentials(t)
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "personal",
		AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, writeCredential(loginRecordName, grant))
	dek := &syncedDEK{Version: 1, APIOrigin: server.URL, UserID: "user_owner", DEKID: randomB64U(16), DEK: make(b64u, 32)}
	require.NoError(t, writeCredential(dekRecordName(server.URL, "user_owner"), dek))
	// A DEK left by an earlier user's interrupted login commit, with no login record of its own.
	service.down = true
	require.NoError(t, writeCredential(dekRecordName(server.URL, "user_earlier"), dek))
	service.down = false

	scope := accountScope{ControlplaneURL: server.URL, UserID: "user_owner"}
	sandboxDir, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111", "work")
	require.NoError(t, err)
	synced, ownSeed := testSeed(t), testSeed(t)
	exported, err := exportTMKIdentity(grant, sandboxDir, synced)
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
	_, err = saveUMKRecord(umkRecord, newUMKRecord("sandbox", ed25519PublicKeyString(ownSeed)))
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
	require.NoError(t, clerkLogout(out))
	require.Contains(t, out.String(), "Could not revoke", "revocation failure is reported but does not stop local cleanup")
	require.Equal(t, "refresh-1", clerk.forms[0].Get("token"))
	gone, err := currentGrant()
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
	_, err = exportTMKIdentity(grant, sandboxDir, synced)
	require.ErrorContains(t, err, "signed out")
	require.ErrorContains(t, whileSignedIn(grant, func() error { _, err := ensureSSHKey(tmkDevice); return err }), "signed out")
	require.NoFileExists(t, exported)
	require.NoFileExists(t, tmkDevice)
}

func mustSigner(t *testing.T, path string) ssh.Signer {
	t.Helper()
	signer, err := loadSigner(path)
	require.NoError(t, err)
	return signer
}

func TestPartialLoginCommitIsRemovedByLogout(t *testing.T) {
	useTestClerk(t, "https://api.example")
	service := useFlakyCredentials(t)
	login, err := credentialFile(loginRecordName)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(login, 0o700), "make the login record unwritable")
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: "https://api.example", ClientID: "fixture-client", UserID: "user_owner", Account: "personal", AccessToken: "a", RefreshToken: "r"}
	dek := &syncedDEK{Version: 1, APIOrigin: "https://api.example", UserID: "user_owner", DEKID: randomB64U(16), DEK: make(b64u, 32)}
	require.NoError(t, writeCredential(dekRecordName(dek.APIOrigin, dek.UserID), dek))
	require.Error(t, commitLogin(t.Context(), grant))
	require.Len(t, service.store, 1, "the DEK was written before the login failed")
	logoutErr := clerkLogout(io.Discard)
	require.Empty(t, service.store, "logout removes a DEK left without a login record")
	require.NoDirExists(t, login)
	if logoutErr != nil {
		require.ErrorContains(t, logoutErr, login)
	}
}

func TestCancelledLoginKeepsThePreviousCredentials(t *testing.T) {
	useTestClerk(t, "https://api.example")
	previous := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: clerkIssuer, ClientID: clerkCLIClientID,
		UserID: "user_owner", Account: "personal", AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, commitLogin(t.Context(), previous))
	dek := &syncedDEK{Version: 1, APIOrigin: fixedAPIOrigin, UserID: previous.UserID, DEKID: randomB64U(16), DEK: make(b64u, 32)}
	require.NoError(t, writeCredential(dekRecordName(dek.APIOrigin, dek.UserID), dek))
	replacement := *previous
	replacement.Grant, replacement.UserID = randomB64U(16), "user_other"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, commitLogin(ctx, &replacement), context.Canceled)
	saved, err := currentGrant()
	require.NoError(t, err)
	require.Equal(t, previous, saved)
	synced, err := syncedKey(saved, saved.UserID)
	require.NoError(t, err)
	require.Equal(t, dek, synced, "a cancelled login must not remove the previous user's synced keys")
}

// terminalBrowser follows the direct OAuth callback, then optionally plays the
// hosted key-sync page. It never gives the hosted page an OAuth code or token.
type terminalBrowser struct {
	t             *testing.T
	envelope      func(keySyncRequest) keySyncEnvelope
	oauthProbe    func(url.Values)
	probe         func(string)
	onSync        func(keySyncRequest) bool
	authorization chan url.Values
	launches      chan keySyncRequest
	location      chan string
}

func (b *terminalBrowser) open(launch string) error {
	u, err := url.Parse(launch)
	require.NoError(b.t, err)
	require.Equal(b.t, clerkIssuer+"/oauth/authorize", strings.Split(launch, "?")[0])
	require.Empty(b.t, u.Fragment)
	query := u.Query()
	require.Len(b.t, query, 8)
	require.Equal(b.t, "code", query.Get("response_type"))
	require.Equal(b.t, "S256", query.Get("code_challenge_method"))
	require.Equal(b.t, oauthCallback, query.Get("redirect_uri"))
	require.Equal(b.t, fixedAPIOrigin, query.Get("resource"))
	b.authorization <- query
	callback := url.Values{"code": {"authorization-code"}, "state": {query.Get("state")}, "iss": {clerkIssuer}}
	target := oauthCallback + "?" + callback.Encode()
	if b.oauthProbe != nil {
		b.oauthProbe(callback)
		target = "http://" + oauthCallbackHost + oauthDonePath
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host != loginCallbackHost && req.URL.Host != oauthCallbackHost {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	resp, err := client.Get(target)
	require.NoError(b.t, err)
	resp.Body.Close()
	require.Equal(b.t, "no-store", resp.Header.Get("Cache-Control"))
	launch = resp.Header.Get("Location")
	if launch == "" {
		b.location <- ""
		return nil
	}
	u, err = url.Parse(launch)
	require.NoError(b.t, err)
	fragment, err := url.ParseQuery(u.Fragment)
	require.NoError(b.t, err)
	public, err := decodeB64U(fragment.Get("hpke_pubkey"), 32)
	require.NoError(b.t, err)
	var expires int64
	fmt.Sscan(fragment.Get("expires"), &expires)
	request := keySyncRequest{HPKEPublicKey: public, Request: fragment.Get("request"), UserID: fragment.Get("user"), Account: fragment.Get("account"), Expires: expires}
	targets, err := fixedKeySyncTargets()
	require.NoError(b.t, err)
	require.Equal(b.t, launch, keySyncLaunchURL(request, targets), "key sync has no OAuth fields or destination overrides")
	grant, err := currentGrant()
	require.NoError(b.t, err)
	require.NotNil(b.t, grant, "authentication is committed before visiting terminal")
	require.Equal(b.t, grant.UserID, request.UserID)
	require.Equal(b.t, grant.Account, request.Account)
	b.launches <- request
	if b.onSync != nil && !b.onSync(request) {
		return nil
	}
	plain, err := contractJSON(b.envelope(request))
	require.NoError(b.t, err)
	key, err := ecdh.X25519().NewPublicKey(public)
	require.NoError(b.t, err)
	recipient, err := hpke.NewDHKEMPublicKey(key)
	require.NoError(b.t, err)
	sealed, err := hpke.Seal(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), keySyncEnvelopeInfo(canonicalKeySyncRequest(request, targets)), plain)
	require.NoError(b.t, err)
	payload := base64.RawURLEncoding.EncodeToString(sealed)
	target = keySyncCallback + "?payload=" + payload
	if b.probe != nil {
		b.probe(payload)
		target = "http://" + loginCallbackHost + loginDonePath
	}
	resp, err = client.Get(target)
	require.NoError(b.t, err)
	resp.Body.Close()
	b.location <- resp.Header.Get("Location")
	return nil
}

func callbackStatus(t *testing.T, target, query, host string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target+"?"+query, nil)
	require.NoError(t, err)
	req.Host = host
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func runLogin(t *testing.T, browser *terminalBrowser, syncKeys bool) error {
	t.Helper()
	previous := openBrowser
	openBrowser = browser.open
	t.Cleanup(func() { openBrowser = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return clerkLogin(cmd, syncKeys)
}

func TestClerkLoginCeremony(t *testing.T) {
	keys := &keyStateServer{}
	clerk := &fakeClerk{user: "user_owner", account: "org_b", keys: keys}
	server := httptest.NewServer(clerk)
	defer server.Close()
	useTestClerk(t, server.URL)
	dek := make([]byte, 32)
	rand.Read(dek)
	dekID := randomB64U(16)
	sealedMK, err := sealMK(&mkPayload{Version: 1, Resources: []mkResource{}}, dek, mkContext{server.URL, "user_owner", dekID})
	require.NoError(t, err)
	keys.revision, keys.dekID, keys.mk = 1, &dekID, &sealedMK
	newBrowser := func(t *testing.T) *terminalBrowser {
		return &terminalBrowser{t: t, authorization: make(chan url.Values, 1), launches: make(chan keySyncRequest, 1), location: make(chan string, 1), envelope: func(r keySyncRequest) keySyncEnvelope {
			return keySyncEnvelope{V: 1, Request: r.Request, UserID: r.UserID, Expires: r.Expires, DEKID: dekID, DEK: dek}
		}}
	}

	t.Run("direct login needs no controlplane, terminal or key material", func(t *testing.T) {
		browser := newBrowser(t)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("login must not contact controlplane")
			http.Error(w, "invalid token", http.StatusUnauthorized)
		}))
		defer api.Close()
		previousAPI := fixedAPIOrigin
		fixedAPIOrigin = api.URL
		defer func() { fixedAPIOrigin = previousAPI }()
		// OAuth works independently of the hosted terminal build profile.
		previous := cliTargets
		cliTargets = "no-terminal-configured"
		defer func() { cliTargets = previous }()
		require.NoError(t, runLogin(t, browser, false))
		require.Empty(t, browser.launches)
		require.Empty(t, <-browser.location)
		grant, err := currentGrant()
		require.NoError(t, err)
		require.Equal(t, "org_b", grant.Account)
		synced, err := syncedKey(grant, grant.UserID)
		require.NoError(t, err)
		require.Nil(t, synced)
		query := <-browser.authorization
		require.Equal(t, "fixture-client", query.Get("client_id"))
		require.Equal(t, "offline_access user:org:read api:full", query.Get("scope"))
		clerk.mu.Lock()
		form := clerk.forms[len(clerk.forms)-1]
		clerk.mu.Unlock()
		require.Equal(t, "authorization_code", form.Get("grant_type"))
		require.Equal(t, "authorization-code", form.Get("code"))
		require.Equal(t, oauthCallback, form.Get("redirect_uri"))
		require.Equal(t, "fixture-client", form.Get("client_id"))
		require.Equal(t, api.URL, form.Get("resource"))
		require.False(t, form.Has("client_secret"))
		challenge := sha256.Sum256([]byte(form.Get("code_verifier")))
		require.Equal(t, query.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(challenge[:]))
	})

	t.Run("each callback validates its binding and is consumed once", func(t *testing.T) {
		browser := newBrowser(t)
		browser.oauthProbe = func(query url.Values) {
			valid := query.Encode()
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, oauthCallback, valid+"&state=other", oauthCallbackHost))
			query.Set("state", randomB64U(32))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, oauthCallback, query.Encode(), oauthCallbackHost))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, oauthCallback, valid, "attacker.example:49152"))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, keySyncCallback, "payload=AAAA", loginCallbackHost))
			require.Equal(t, http.StatusSeeOther, callbackStatus(t, oauthCallback, valid, oauthCallbackHost))
			require.Equal(t, http.StatusConflict, callbackStatus(t, oauthCallback, valid, oauthCallbackHost))
		}
		browser.probe = func(payload string) {
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, keySyncCallback, "payload="+payload+"&payload="+payload, loginCallbackHost))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, keySyncCallback, "payload="+payload+"&dest=evil", loginCallbackHost))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, keySyncCallback, "payload="+payload, "attacker.example:49152"))
			require.Equal(t, http.StatusBadRequest, callbackStatus(t, keySyncCallback, "payload=AAAA", loginCallbackHost))
			require.Equal(t, http.StatusSeeOther, callbackStatus(t, keySyncCallback, "payload="+payload, loginCallbackHost))
			require.Equal(t, http.StatusConflict, callbackStatus(t, keySyncCallback, "payload="+payload, loginCallbackHost))
		}
		require.NoError(t, runLogin(t, browser, true))
		request := <-browser.launches
		targets, err := fixedKeySyncTargets()
		require.NoError(t, err)
		require.Equal(t, keySyncCompletionURL(targets, request.Request, "user_owner", "org_b"), <-browser.location)
		grant, err := currentGrant()
		require.NoError(t, err)
		synced, err := syncedKey(grant, grant.UserID)
		require.NoError(t, err)
		require.Equal(t, dekID, synced.DEKID)
		require.Equal(t, dek, []byte(synced.DEK))
	})

	t.Run("wrong key leaves the successful login intact", func(t *testing.T) {
		require.NoError(t, clerkLogout(io.Discard))
		browser := newBrowser(t)
		browser.envelope = func(r keySyncRequest) keySyncEnvelope {
			return keySyncEnvelope{V: 1, Request: r.Request, UserID: r.UserID, Expires: r.Expires, DEKID: randomB64U(16), DEK: dek}
		}
		require.ErrorContains(t, runLogin(t, browser, true), "signed in, but key sync failed")
		require.Empty(t, <-browser.location)
		grant, err := currentGrant()
		require.NoError(t, err)
		require.NotNil(t, grant)
		synced, err := syncedKey(grant, grant.UserID)
		require.NoError(t, err)
		require.Nil(t, synced)
	})

	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("late sync cannot overwrite logout or a replacement login %t", replace), func(t *testing.T) {
			browser := newBrowser(t)
			var replacement *clerkGrant
			browser.onSync = func(keySyncRequest) bool {
				clerk.mu.Lock()
				clerk.beforeKeys = func() {
					require.NoError(t, clerkLogout(io.Discard))
					if replace {
						replacement = &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: clerkIssuer, ClientID: clerkCLIClientID,
							UserID: "user_owner", Account: "personal", AccessToken: "access-new", RefreshToken: "refresh-new", ExpiresAt: time.Now().Add(time.Hour).Unix()}
						require.NoError(t, commitLogin(t.Context(), replacement))
					}
				}
				clerk.mu.Unlock()
				return true
			}
			require.ErrorContains(t, runLogin(t, browser, true), "signed out")
			grant, err := currentGrant()
			require.NoError(t, err)
			if replace {
				require.Equal(t, replacement, grant)
			} else {
				require.Nil(t, grant)
			}
			var synced syncedDEK
			found, err := readCredential(dekRecordName(server.URL, "user_owner"), &synced)
			require.NoError(t, err)
			require.False(t, found)
		})
	}

	t.Run("Clerk refuses the code before terminal is involved", func(t *testing.T) {
		require.NoError(t, clerkLogout(io.Discard))
		clerk.codeErr = "invalid_grant"
		defer func() { clerk.codeErr = "" }()
		browser := newBrowser(t)
		require.ErrorContains(t, runLogin(t, browser, true), "invalid_grant")
		require.Empty(t, browser.launches)
		require.Empty(t, <-browser.location)
		grant, err := currentGrant()
		require.NoError(t, err)
		require.Nil(t, grant)
	})

	for _, badUser := range []bool{true, false} {
		t.Run(fmt.Sprintf("invalid Clerk identity is not saved, user %t", badUser), func(t *testing.T) {
			require.NoError(t, clerkLogout(io.Discard))
			user, account := clerk.user, clerk.account
			defer func() { clerk.user, clerk.account = user, account }()
			if badUser {
				clerk.user = "not-a-user"
			} else {
				clerk.account = "not-an-account"
			}
			browser := newBrowser(t)
			require.ErrorContains(t, runLogin(t, browser, true), "invalid login identity")
			require.Empty(t, browser.launches)
			grant, err := currentGrant()
			require.NoError(t, err)
			require.Nil(t, grant)
		})
	}

	for _, syncKeys := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancellation preserves only a completed login %t", syncKeys), func(t *testing.T) {
			require.NoError(t, clerkLogout(io.Discard))
			previous := openBrowser
			defer func() { openBrowser = previous }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			browser := newBrowser(t)
			if syncKeys {
				browser.onSync = func(keySyncRequest) bool { cancel(); return false }
				openBrowser = browser.open
			} else {
				openBrowser = func(string) error { cancel(); return nil }
			}
			cmd := &cobra.Command{}
			cmd.SetContext(ctx)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			failure := "sign-in did not complete"
			if syncKeys {
				failure = "signed in, but key sync did not complete"
			}
			require.ErrorContains(t, clerkLogin(cmd, syncKeys), failure)
			grant, err := currentGrant()
			require.NoError(t, err)
			require.Equal(t, syncKeys, grant != nil)
			listener, err := net.Listen("tcp4", "127.0.0.1:"+loginListenPort)
			require.NoError(t, err)
			listener.Close()
		})
	}

	t.Run("occupied port fails before launch", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", "127.0.0.1:"+loginListenPort)
		require.NoError(t, err)
		defer occupied.Close()
		browser := newBrowser(t)
		require.ErrorContains(t, runLogin(t, browser, false), "port "+loginListenPort)
		require.Empty(t, browser.authorization)
	})

	t.Run("unconfigured build fails closed", func(t *testing.T) {
		clerkCLIClientID = ""
		browser := newBrowser(t)
		require.ErrorContains(t, runLogin(t, browser, false), "not configured")
		require.Empty(t, browser.authorization)
	})
}

func TestDirectOAuthCallbackValidation(t *testing.T) {
	state := randomB64U(32)
	valid := url.Values{"code": {"code"}, "state": {state}}
	for _, issuer := range []bool{false, true} {
		query := valid.Encode()
		if issuer {
			query += "&iss=" + url.QueryEscape(clerkIssuer)
		}
		code, failure, err := parseOAuthCallback(query, state)
		require.NoError(t, err)
		require.Equal(t, "code", code)
		require.Empty(t, failure)
	}
	_, failure, err := parseOAuthCallback(url.Values{"error": {"access_denied"}, "state": {state}}.Encode(), state)
	require.NoError(t, err)
	require.Equal(t, "access_denied", failure)
	for _, query := range []string{
		"code=code", "code=code&state=wrong", valid.Encode() + "&state=" + state,
		valid.Encode() + "&iss=https://evil.example", valid.Encode() + "&iss=", valid.Encode() + "&code=second",
		valid.Encode() + "&error=access_denied", valid.Encode() + "&error_description=unexpected",
		valid.Encode() + "&redirect_uri=https://evil.example", "code=" + strings.Repeat("x", 2049) + "&state=" + state,
		"code=%00&state=" + state, valid.Encode() + "&x=%xx",
	} {
		_, _, err := parseOAuthCallback(query, state)
		require.Error(t, err, query)
	}
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
	require.ErrorContains(t, err, "another origin")
	require.Zero(t, requests, "the bearer token never follows a cross-origin redirect")

	// An explicit admin key keeps its own configured target and never sees the Clerk token.
	t.Setenv(envAdminKey, "admin_automation")
	cfg, err = requireAuth()
	require.NoError(t, err)
	require.Nil(t, cfg.login)
	require.Equal(t, other.URL, cfg.ControlplaneURL)
}

func TestUnauthenticatedListDoesNotClaimAnEmptyAccount(t *testing.T) {
	useTestClerk(t, "https://api.example")
	for _, kind := range []string{"sandbox", "monitor"} {
		cmd := newManagedStatusCmd(kind)
		out, err := captureTestStdout(func() error { return cmd.RunE(cmd, nil) })
		require.NoError(t, err)
		require.Contains(t, string(out), "stored on this machine")
		require.Contains(t, string(out), "tinfoil login")
		_, err = captureTestStdout(func() error { return cmd.RunE(cmd, []string{"work"}) })
		require.ErrorIs(t, err, errNotLoggedIn)
	}
}

func TestLogoutRemovesSavedAdminKeyDespiteCredentialServiceOutage(t *testing.T) {
	useTestClerk(t, "https://api.example")
	service := useFlakyCredentials(t)
	path, err := saveConfig(cliConfig{ControlplaneURL: "https://api.example", APIKey: "admin_saved_secret"})
	require.NoError(t, err)
	require.NoError(t, writeCredential(loginRecordName, &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: "https://api.example", ClientID: "fixture-client",
		UserID: "user_owner", Account: "personal", AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}))
	owner := ed25519PublicKeyString(testSeed(t))
	umk, err := umkRecordPath(accountScope{ControlplaneURL: "https://api.example", UserID: "user_owner"}, testContainerID)
	require.NoError(t, err)
	_, err = saveUMKRecord(umk, newUMKRecord("sandbox", owner))
	require.NoError(t, err)
	t.Setenv(envAPIKey, "admin_environment_secret")

	service.down = true
	var logoutErr error
	warning, err := captureTestStderr(func() error {
		_, logoutErr = captureTestStdout(func() error { return logoutCmd.RunE(logoutCmd, nil) })
		return nil
	})
	require.NoError(t, err)
	require.ErrorContains(t, logoutErr, "still holds a copy", "incomplete keyring cleanup is reported")
	require.NoFileExists(t, path, "the saved admin key is removed anyway")
	require.Contains(t, string(warning), envAPIKey+" is still active")
	require.FileExists(t, umk)

	service.down = false
	grant, err := currentGrant()
	require.NoError(t, err)
	require.Nil(t, grant, "the login stays removed after the service recovers")
	require.Contains(t, service.store, loginRecordName)
	_, err = captureTestStdout(func() error { return logoutCmd.RunE(logoutCmd, nil) })
	require.NoError(t, err, "a later logout finishes the cleanup")
	require.Empty(t, service.store)
}
