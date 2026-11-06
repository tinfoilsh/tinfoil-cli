package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

func fixtureGrant(service *Service, user string) *Grant {
	return &Grant{Version: 1, Grant: randomB64U(16), Issuer: service.settings.Issuer, ClientID: service.settings.ClientID,
		UserID: user, Account: "personal", AccessToken: "access-fixture", ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func assertCredentialLock(t *testing.T, store *Store) {
	t.Helper()
	unlock, err := statefile.Lock(store.file("credentials"))
	if unlock != nil {
		unlock()
	}
	assert.ErrorIs(t, err, statefile.ErrLocked)
}

func TestLifecycleCleanupSharesTheActiveGrantTransaction(t *testing.T) {
	for _, switching := range []bool{false, true} {
		name := "logout"
		if switching {
			name = "account switch"
		}
		t.Run(name, func(t *testing.T) {
			service := testService(t, "https://api.example")
			previous := fixtureGrant(service, "user_previous")
			require.NoError(t, service.commitLogin(t.Context(), previous))
			dekName := dekRecordName(service.settings.APIOrigin, previous.UserID)
			require.NoError(t, service.store.write(dekName, SyncedDEK{Version: 1}))
			path := filepath.Join(t.TempDir(), "owner-key")
			service.lifecycle.CleanupResources = func() error {
				assertCredentialLock(t, service.store)
				grant, err := service.CurrentGrant()
				assert.NoError(t, err)
				assert.Nil(t, grant, "cleanup precedes publication of a replacement grant")
				var dek SyncedDEK
				found, err := service.store.read(dekName, &dek)
				assert.NoError(t, err)
				assert.False(t, found)
				data, err := os.ReadFile(path)
				assert.NoError(t, err)
				assert.Equal(t, "exported material", string(data))
				return os.Remove(path)
			}

			started, release := make(chan struct{}), make(chan struct{})
			exported := make(chan error, 1)
			go func() {
				exported <- service.WhileSignedIn(previous, func() error {
					close(started)
					<-release
					return os.WriteFile(path, []byte("exported material"), 0o600)
				})
			}()
			<-started
			assertCredentialLock(t, service.store)
			replacement := fixtureGrant(service, "user_replacement")
			completed := make(chan error, 1)
			go func() {
				if switching {
					completed <- service.commitLogin(t.Context(), replacement)
				} else {
					_, err := service.Logout(t.Context())
					completed <- err
				}
			}()
			close(release)
			require.NoError(t, <-exported)
			require.NoError(t, <-completed)
			require.NoFileExists(t, path)
			require.ErrorContains(t, service.WhileSignedIn(previous, func() error {
				return os.WriteFile(path, []byte("resurrected material"), 0o600)
			}), "signed out")
			require.NoFileExists(t, path)
			current, err := service.CurrentGrant()
			require.NoError(t, err)
			if switching {
				require.Equal(t, replacement, current)
			} else {
				require.Nil(t, current)
			}
		})
	}
}

func TestAccountSwitchDoesNotPublishAfterCleanupFailure(t *testing.T) {
	service := testService(t, "https://api.example")
	previous := fixtureGrant(service, "user_previous")
	require.NoError(t, service.commitLogin(t.Context(), previous))
	cleanupErr := errors.New("exported key could not be removed")
	service.lifecycle.CleanupResources = func() error {
		assertCredentialLock(t, service.store)
		return cleanupErr
	}
	replacement := fixtureGrant(service, "user_replacement")
	require.ErrorIs(t, service.commitLogin(t.Context(), replacement), cleanupErr)
	current, err := service.CurrentGrant()
	require.NoError(t, err)
	require.Nil(t, current)
	_, err = service.TokenSource(previous).Token(t.Context())
	require.ErrorContains(t, err, "login has ended")
}

func TestLoginCommitFollowupRunsUnderTheCredentialLock(t *testing.T) {
	service := testService(t, "https://api.example")
	grant := fixtureGrant(service, "user_owner")
	followupErr := errors.New("saved admin credential could not be removed")
	service.lifecycle.LoginCommitted = func() error {
		assertCredentialLock(t, service.store)
		current, err := service.CurrentGrant()
		require.NoError(t, err)
		require.Equal(t, grant, current)
		return followupErr
	}
	require.ErrorIs(t, service.commitLogin(t.Context(), grant), followupErr)
	current, err := service.CurrentGrant()
	require.NoError(t, err)
	require.Equal(t, grant, current, "the completed credential write survives a followup failure")

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, service.commitLogin(canceled, fixtureGrant(service, "user_other")), context.Canceled)
	current, err = service.CurrentGrant()
	require.NoError(t, err)
	require.Equal(t, grant, current)
}

func TestServiceConstructionDoesNotAccessCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	store := NewStore(dir, nil)
	service := New(BuildSettings{}, store, nil, "lazy-test", Lifecycle{})
	service.TokenSource(nil)
	require.NoDirExists(t, dir)
}
