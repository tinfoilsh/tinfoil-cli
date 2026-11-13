package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

func TestInjectedClientAndVersionReachClerkAndKeySync(t *testing.T) {
	var state controlplane.KeyState
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer access-fixture", r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/oauth/userinfo":
			io.WriteString(w, `{"sub":"user_owner"}`)
		case controlplane.KeyStatePath:
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "tinfoil-cli/auth-test", r.Header.Get("User-Agent"))
			json.NewEncoder(w).Encode(state)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	fixture := testService(t, server.URL)
	service := New(fixture.settings, fixture.store, server.Client(), "auth-test", Lifecycle{})
	user, account, _, _, err := service.clerkIdentity(t.Context(), "access-fixture")
	require.NoError(t, err)
	require.Equal(t, "user_owner", user)
	require.Equal(t, "personal", account)

	grant := fixtureGrant(service, user)
	require.NoError(t, service.commitLogin(t.Context(), grant))
	dek, dekID := make([]byte, 32), randomB64U(16)
	encrypted, err := keybundle.Seal(&keybundle.Payload{Version: 1, Resources: []keybundle.Resource{}}, dek,
		keybundle.Context{APIOrigin: server.URL, UserID: user, DEKID: dekID})
	require.NoError(t, err)
	state = controlplane.KeyState{DEKID: &dekID, EncryptedMK: &encrypted}
	targets, err := service.settings.syncTargets()
	require.NoError(t, err)
	ceremony := loginCeremony{service: service, ctx: t.Context(), grant: grant, targets: targets}
	require.NoError(t, ceremony.saveSyncedKey(&keybundle.SyncEnvelope{DEKID: dekID, DEK: dek}))
	saved, err := service.SyncedKey(grant, user)
	require.NoError(t, err)
	require.Equal(t, dek, []byte(saved.DEK))
}

func TestInjectedRedirectPolicyCannotForwardCredentials(t *testing.T) {
	var forwarded atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	fixture := testService(t, server.URL)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	service := New(fixture.settings, fixture.store, client, "auth-test", Lifecycle{})
	_, _, _, _, err := service.clerkIdentity(t.Context(), "access-fixture")
	require.ErrorContains(t, err, "307")
	grant := fixtureGrant(service, "user_owner")
	require.NoError(t, service.commitLogin(t.Context(), grant))
	targets, err := service.settings.syncTargets()
	require.NoError(t, err)
	ceremony := loginCeremony{service: service, ctx: t.Context(), grant: grant, targets: targets}
	err = ceremony.saveSyncedKey(&keybundle.SyncEnvelope{})
	require.ErrorContains(t, err, "refusing a controlplane redirect")
	require.Zero(t, forwarded.Load())
}
