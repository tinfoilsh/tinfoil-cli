package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
)

func TestTreesOwnTheirCredentialsBuildSettingsAndClientVersions(t *testing.T) {
	t.Setenv(envAdminKey, "")
	t.Setenv(envAPIKey, "")
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv(envCPURL, "https://unused.invalid")
	type requestLog struct {
		sync.Mutex
		paths []string
	}
	type invocation struct {
		root        *cobra.Command
		out         *bytes.Buffer
		keyring     *flakyCredentials
		user, token string
		requests    *requestLog
	}
	var invocations []invocation
	for _, suffix := range []string{"first", "second"} {
		user, token, clientID := "user_"+suffix, "access-"+suffix, "client-"+suffix
		currentVersion := "version-" + suffix
		requests := &requestLog{}
		var origin string
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Lock()
			requests.paths = append(requests.paths, r.URL.Path)
			requests.Unlock()
			switch r.URL.Path {
			case "/oauth/token":
				assert.NoError(t, r.ParseForm())
				assert.Equal(t, clientID, r.Form.Get("client_id"))
				assert.Equal(t, origin, r.Form.Get("resource"))
				assert.Equal(t, "refresh-"+suffix, r.Form.Get("refresh_token"))
				json.NewEncoder(w).Encode(map[string]any{"access_token": token, "refresh_token": "renewed-" + suffix, "token_type": "bearer", "expires_in": 3600})
			case "/oauth/userinfo":
				assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
				json.NewEncoder(w).Encode(map[string]string{"sub": user})
			case "/api/auth/context":
				assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
				assert.Equal(t, "tinfoil-cli/"+currentVersion, r.Header.Get("User-Agent"))
				json.NewEncoder(w).Encode(authContext{ContextType: "personal", UserID: user})
			default:
				t.Errorf("unexpected request %s", r.URL)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(server.Close)
		origin = server.URL
		settings := auth.BuildSettings{Targets: "production", ClientID: clientID, APIScope: "api:" + suffix, Issuer: origin, APIOrigin: origin}
		grant := clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: origin, ClientID: clientID, UserID: user, Account: "personal", AccessToken: "expired-" + suffix, RefreshToken: "refresh-" + suffix}
		raw, err := json.Marshal(grant)
		require.NoError(t, err)
		keyring := &flakyCredentials{store: map[string]string{loginRecordName: string(raw)}}
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, loginRecordName+".json"), []byte(`{"keyring":true}`), 0600))
		var storeCalls atomic.Int32
		out := &bytes.Buffer{}
		root := newRootCommandWithDependencies(commandDependencies{
			version: currentVersion, authSettings: &settings, accountHTTP: server.Client(), out: out, err: io.Discard,
			credentials: func() (*auth.Store, error) {
				storeCalls.Add(1)
				return auth.NewStore(dir, keyring), nil
			},
		})
		require.Zero(t, storeCalls.Load(), "construction must not access credentials")
		settings.ClientID = "invalid!"
		root.SetArgs([]string{"whoami"})
		invocations = append(invocations, invocation{root: root, out: out, keyring: keyring, user: user, token: token, requests: requests})
	}
	for _, call := range invocations {
		require.NoError(t, call.root.Execute())
		require.Contains(t, call.out.String(), call.user)
		call.requests.Lock()
		paths := append([]string(nil), call.requests.paths...)
		call.requests.Unlock()
		require.Equal(t, []string{"/oauth/token", "/oauth/userinfo", "/api/auth/context"}, paths)
		var saved clerkGrant
		require.NoError(t, json.Unmarshal([]byte(call.keyring.store[loginRecordName]), &saved))
		require.Equal(t, call.token, saved.AccessToken)
	}
}
