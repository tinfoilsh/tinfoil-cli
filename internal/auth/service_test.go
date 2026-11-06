package auth

import (
	"context"
	"crypto/ecdh"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"github.com/zalando/go-keyring"
)

func testService(t *testing.T, origin string) *Service {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "credentials"), &flakyCredentials{store: map[string]string{}})
	return New(BuildSettings{Targets: "production", ClientID: "fixture-client", APIScope: "api:full", Issuer: origin, APIOrigin: origin}, store, http.DefaultClient, "auth-test", Lifecycle{})
}

func logout(service *Service) error {
	_, err := service.Logout(context.Background())
	return err
}

type keyStateServer struct {
	revision uint64
	dekID    *string
	mk       *string
}

func (s *keyStateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.URL.Path != controlplane.KeyStatePath {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(controlplane.KeyState{Revision: s.revision, DEKID: s.dekID, EncryptedMK: s.mk, Recovery: json.RawMessage("[]")})
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

func TestCredentialStoreSurvivesServiceOutagesWithoutResurrection(t *testing.T) {
	auth := testService(t, "https://api.example")
	service := auth.store.keyring.(*flakyCredentials)
	type record struct{ Token string }
	read := func() (string, error) {
		var got record
		found, err := auth.store.read(loginRecordName, &got)
		if !found {
			return "", err
		}
		return got.Token, err
	}
	slot := auth.store.file(loginRecordName)

	service.onSet = func(user string) {
		var selector struct{ Keyring bool }
		require.NoError(t, statefile.ReadJSON(slot, &selector), "the selector exists before the service holds a copy")
		require.True(t, selector.Keyring)
	}
	require.NoError(t, auth.store.write(loginRecordName, record{"first"}))
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
	require.NoError(t, auth.store.write(loginRecordName, record{"rotated"}))
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

	require.NoError(t, auth.store.write(loginRecordName, record{"third"}))
	data, err = os.ReadFile(slot)
	require.NoError(t, err)
	require.NotContains(t, string(data), "rotated", "a recovered service takes the record back out of the file")
	token, err = read()
	require.NoError(t, err)
	require.Equal(t, "third", token)

	// A deletion during an outage fails visibly and stays deleted after recovery.
	service.down = true
	require.ErrorContains(t, auth.store.delete(loginRecordName), "still holds a copy")
	token, err = read()
	require.NoError(t, err)
	require.Empty(t, token)
	service.down = false
	token, err = read()
	require.NoError(t, err)
	require.Empty(t, token, "a recovered service must not resurrect a deleted record")
	require.Contains(t, service.store, loginRecordName)
	require.NoError(t, auth.store.delete(loginRecordName))
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
				assert.Equal(t, "GET /oauth/userinfo", r.Method+" "+r.URL.Path)
				assert.Empty(t, r.URL.RawQuery)
				assert.Equal(t, "Bearer access-1", r.Header.Get("Authorization"))
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.reply)
			}))
			defer server.Close()
			service := testService(t, server.URL)
			user, account, err := service.clerkIdentity(t.Context(), "access-1")
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

func TestTokenRenewalIsSerializedAndKeepsTheGrantedAccount(t *testing.T) {
	clerk := &fakeClerk{user: "user_owner", account: "org_b"}
	server := httptest.NewServer(clerk)
	defer server.Close()
	service := testService(t, server.URL)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token renewal must not contact controlplane")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer api.Close()
	service.settings.APIOrigin = api.URL
	expired := Grant{Version: 1, Grant: randomB64U(16), Issuer: server.URL, ClientID: "fixture-client", UserID: "user_owner", Account: "org_b",
		AccessToken: "stale", RefreshToken: "refresh-0", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	require.NoError(t, service.store.write(loginRecordName, &expired))

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
			token, err := service.TokenSource(grant).Token(t.Context())
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
	current, err := service.CurrentGrant()
	require.NoError(t, err)
	require.Equal(t, "refresh-1", current.RefreshToken)

	// A renewal that comes back for another account is refused and not saved.
	current.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	require.NoError(t, service.store.write(loginRecordName, current))
	for _, identity := range [][2]string{{"user_owner", "personal"}, {"user_owner", "org_other"}, {"user_other", "org_b"}} {
		clerk.user, clerk.account = identity[0], identity[1]
		_, err = service.TokenSource(current).Token(t.Context())
		require.ErrorContains(t, err, "different account")
		saved, err := service.CurrentGrant()
		require.NoError(t, err)
		require.Equal(t, current, saved)
	}
	clerk.user = "user_owner"

	clerk.account, clerk.refreshErr = "org_b", "invalid_grant"
	_, err = service.TokenSource(current).Token(t.Context())
	require.ErrorContains(t, err, "run `tinfoil login`")

	// After logout, a command still holding the old grant cannot use, renew or recreate it.
	clerk.refreshErr = ""
	fresh := *current
	fresh.ExpiresAt = time.Now().Add(time.Hour).Unix()
	require.NoError(t, service.store.write(loginRecordName, &fresh))
	token, err := service.TokenSource(&fresh).Token(t.Context())
	require.NoError(t, err)
	require.Equal(t, fresh.AccessToken, token)
	require.NoError(t, logout(service))
	_, err = service.TokenSource(&fresh).Token(t.Context())
	require.ErrorContains(t, err, "login has ended", "a cached token is not admitted after logout")
	_, err = service.TokenSource(current).Token(t.Context())
	require.ErrorContains(t, err, "login has ended")
	gone, err := service.CurrentGrant()
	require.NoError(t, err)
	require.Nil(t, gone)
}

// terminalBrowser follows the direct OAuth callback, then optionally plays the
// hosted key-sync page. It never gives the hosted page an OAuth code or token.
type terminalBrowser struct {
	service       *Service
	t             *testing.T
	envelope      func(keybundle.SyncRequest) keybundle.SyncEnvelope
	oauthProbe    func(url.Values)
	probe         func(string)
	onSync        func(keybundle.SyncRequest) bool
	authorization chan url.Values
	launches      chan keybundle.SyncRequest
	location      chan string
}

func (b *terminalBrowser) open(launch string) error {
	service := b.service
	u, err := url.Parse(launch)
	require.NoError(b.t, err)
	require.Equal(b.t, service.settings.Issuer+"/oauth/authorize", strings.Split(launch, "?")[0])
	require.Empty(b.t, u.Fragment)
	query := u.Query()
	require.Len(b.t, query, 8)
	require.Equal(b.t, "code", query.Get("response_type"))
	require.Equal(b.t, "S256", query.Get("code_challenge_method"))
	require.Equal(b.t, oauthCallback, query.Get("redirect_uri"))
	require.Equal(b.t, service.settings.APIOrigin, query.Get("resource"))
	b.authorization <- query
	callback := url.Values{"code": {"authorization-code"}, "state": {query.Get("state")}, "iss": {service.settings.Issuer}}
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
	public, err := keybundle.DecodeBase64URL(fragment.Get("hpke_pubkey"), 32)
	require.NoError(b.t, err)
	var expires int64
	fmt.Sscan(fragment.Get("expires"), &expires)
	request := keybundle.SyncRequest{HPKEPublicKey: public, Request: fragment.Get("request"), UserID: fragment.Get("user"), Account: fragment.Get("account"), Expires: expires}
	targets, err := service.settings.syncTargets()
	require.NoError(b.t, err)
	require.Equal(b.t, launch, keybundle.LaunchURL(request, targets), "key sync has no OAuth fields or destination overrides")
	grant, err := service.CurrentGrant()
	require.NoError(b.t, err)
	require.NotNil(b.t, grant, "authentication is committed before visiting terminal")
	require.Equal(b.t, grant.UserID, request.UserID)
	require.Equal(b.t, grant.Account, request.Account)
	b.launches <- request
	if b.onSync != nil && !b.onSync(request) {
		return nil
	}
	plain, err := keybundle.Marshal(b.envelope(request))
	require.NoError(b.t, err)
	key, err := ecdh.X25519().NewPublicKey(public)
	require.NoError(b.t, err)
	recipient, err := hpke.NewDHKEMPublicKey(key)
	require.NoError(b.t, err)
	const envelopeLabel = "tinfoil-cli-key-sync-envelope-v1\x00"
	digest := sha256.Sum256(keybundle.CanonicalRequest(request, targets))
	info := append([]byte(envelopeLabel), digest[:]...)
	sealed, err := hpke.Seal(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), info, plain)
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, err := browser.service.Login(ctx, syncKeys, LoginProgress{Authorize: func(launch string) { go browser.open(launch) }})
	if err == nil {
		require.NotNil(t, result.Grant)
		require.Equal(t, syncKeys, result.KeysSynced)
	}
	return err
}

func TestClerkLoginCeremony(t *testing.T) {
	keys := &keyStateServer{}
	clerk := &fakeClerk{user: "user_owner", account: "org_b", keys: keys}
	server := httptest.NewServer(clerk)
	defer server.Close()
	service := testService(t, server.URL)
	dek := make([]byte, 32)
	rand.Read(dek)
	dekID := randomB64U(16)
	sealedMK, err := keybundle.Seal(&keybundle.Payload{Version: 1, Resources: []keybundle.Resource{}}, dek, keybundle.Context{APIOrigin: server.URL, UserID: "user_owner", DEKID: dekID})
	require.NoError(t, err)
	keys.revision, keys.dekID, keys.mk = 1, &dekID, &sealedMK
	newBrowser := func(t *testing.T) *terminalBrowser {
		return &terminalBrowser{t: t, service: service, authorization: make(chan url.Values, 1), launches: make(chan keybundle.SyncRequest, 1), location: make(chan string, 1), envelope: func(r keybundle.SyncRequest) keybundle.SyncEnvelope {
			return keybundle.SyncEnvelope{V: 1, Request: r.Request, UserID: r.UserID, Expires: r.Expires, DEKID: dekID, DEK: dek}
		}}
	}

	t.Run("direct login needs no controlplane, terminal or key material", func(t *testing.T) {
		browser := newBrowser(t)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("login must not contact controlplane")
			http.Error(w, "invalid token", http.StatusUnauthorized)
		}))
		defer api.Close()
		previousAPI := service.settings.APIOrigin
		service.settings.APIOrigin = api.URL
		defer func() { service.settings.APIOrigin = previousAPI }()
		// OAuth works independently of the hosted terminal build profile.
		previous := service.settings.Targets
		service.settings.Targets = "no-terminal-configured"
		defer func() { service.settings.Targets = previous }()
		require.NoError(t, runLogin(t, browser, false))
		require.Empty(t, browser.launches)
		require.Empty(t, <-browser.location)
		grant, err := service.CurrentGrant()
		require.NoError(t, err)
		require.Equal(t, "org_b", grant.Account)
		synced, err := service.SyncedKey(grant, grant.UserID)
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
		targets, err := service.settings.syncTargets()
		require.NoError(t, err)
		require.Equal(t, keybundle.CompletionURL(targets, request.Request, "user_owner", "org_b"), <-browser.location)
		grant, err := service.CurrentGrant()
		require.NoError(t, err)
		synced, err := service.SyncedKey(grant, grant.UserID)
		require.NoError(t, err)
		require.Equal(t, dekID, synced.DEKID)
		require.Equal(t, dek, []byte(synced.DEK))
	})

	t.Run("wrong key leaves the successful login intact", func(t *testing.T) {
		require.NoError(t, logout(service))
		browser := newBrowser(t)
		browser.envelope = func(r keybundle.SyncRequest) keybundle.SyncEnvelope {
			return keybundle.SyncEnvelope{V: 1, Request: r.Request, UserID: r.UserID, Expires: r.Expires, DEKID: randomB64U(16), DEK: dek}
		}
		require.ErrorContains(t, runLogin(t, browser, true), "signed in, but key sync failed")
		require.Empty(t, <-browser.location)
		grant, err := service.CurrentGrant()
		require.NoError(t, err)
		require.NotNil(t, grant)
		synced, err := service.SyncedKey(grant, grant.UserID)
		require.NoError(t, err)
		require.Nil(t, synced)
	})

	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("late sync cannot overwrite logout or a replacement login %t", replace), func(t *testing.T) {
			browser := newBrowser(t)
			var replacement *Grant
			browser.onSync = func(keybundle.SyncRequest) bool {
				clerk.mu.Lock()
				clerk.beforeKeys = func() {
					require.NoError(t, logout(service))
					if replace {
						replacement = &Grant{Version: 1, Grant: randomB64U(16), Issuer: service.settings.Issuer, ClientID: service.settings.ClientID,
							UserID: "user_owner", Account: "personal", AccessToken: "access-new", RefreshToken: "refresh-new", ExpiresAt: time.Now().Add(time.Hour).Unix()}
						require.NoError(t, service.commitLogin(t.Context(), replacement))
					}
				}
				clerk.mu.Unlock()
				return true
			}
			require.ErrorContains(t, runLogin(t, browser, true), "signed out")
			grant, err := service.CurrentGrant()
			require.NoError(t, err)
			if replace {
				require.Equal(t, replacement, grant)
			} else {
				require.Nil(t, grant)
			}
			var synced SyncedDEK
			found, err := service.store.read(dekRecordName(server.URL, "user_owner"), &synced)
			require.NoError(t, err)
			require.False(t, found)
		})
	}

	t.Run("Clerk refuses the code before terminal is involved", func(t *testing.T) {
		require.NoError(t, logout(service))
		clerk.codeErr = "invalid_grant"
		defer func() { clerk.codeErr = "" }()
		browser := newBrowser(t)
		require.ErrorContains(t, runLogin(t, browser, true), "invalid_grant")
		require.Empty(t, browser.launches)
		require.Empty(t, <-browser.location)
		grant, err := service.CurrentGrant()
		require.NoError(t, err)
		require.Nil(t, grant)
	})

	for _, badUser := range []bool{true, false} {
		t.Run(fmt.Sprintf("invalid Clerk identity is not saved, user %t", badUser), func(t *testing.T) {
			require.NoError(t, logout(service))
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
			grant, err := service.CurrentGrant()
			require.NoError(t, err)
			require.Nil(t, grant)
		})
	}

	for _, syncKeys := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancellation preserves only a completed login %t", syncKeys), func(t *testing.T) {
			require.NoError(t, logout(service))
			var openBrowser func(string) error
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			browser := newBrowser(t)
			if syncKeys {
				browser.onSync = func(keybundle.SyncRequest) bool { cancel(); return false }
				openBrowser = browser.open
			} else {
				openBrowser = func(string) error { cancel(); return nil }
			}

			failure := "sign-in did not complete"
			if syncKeys {
				failure = "signed in, but key sync did not complete"
			}
			result, err := service.Login(ctx, syncKeys, LoginProgress{Authorize: func(launch string) { go openBrowser(launch) }})
			require.ErrorContains(t, err, failure)
			require.Equal(t, syncKeys, result.Grant != nil)
			require.False(t, result.KeysSynced)
			grant, err := service.CurrentGrant()
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
		service.settings.ClientID = ""
		browser := newBrowser(t)
		require.ErrorContains(t, runLogin(t, browser, false), "not configured")
		require.Empty(t, browser.authorization)
	})
}

func TestDirectOAuthCallbackValidation(t *testing.T) {
	service := testService(t, "https://clerk.example")
	state := randomB64U(32)
	valid := url.Values{"code": {"code"}, "state": {state}}
	for _, issuer := range []bool{false, true} {
		query := valid.Encode()
		if issuer {
			query += "&iss=" + url.QueryEscape(service.settings.Issuer)
		}
		code, failure, err := parseOAuthCallback(query, state, service.settings.Issuer)
		require.NoError(t, err)
		require.Equal(t, "code", code)
		require.Empty(t, failure)
	}
	_, failure, err := parseOAuthCallback(url.Values{"error": {"access_denied"}, "state": {state}}.Encode(), state, service.settings.Issuer)
	require.NoError(t, err)
	require.Equal(t, "access_denied", failure)
	for _, query := range []string{
		"code=code", "code=code&state=wrong", valid.Encode() + "&state=" + state,
		valid.Encode() + "&iss=https://evil.example", valid.Encode() + "&iss=", valid.Encode() + "&code=second",
		valid.Encode() + "&error=access_denied", valid.Encode() + "&error_description=unexpected",
		valid.Encode() + "&redirect_uri=https://evil.example", "code=" + strings.Repeat("x", 2049) + "&state=" + state,
		"code=%00&state=" + state, valid.Encode() + "&x=%xx",
	} {
		_, _, err := parseOAuthCallback(query, state, service.settings.Issuer)
		require.Error(t, err, query)
	}
}
