package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

const (
	oauthCallback    = "http://127.0.0.1:49152/oauth/callback"
	keySyncCallback  = "http://localhost:49152/callback"
	loginRecordName  = "login"
	accessTokenSlack = 60
)

var (
	clerkClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	clerkScopePattern    = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,128}$`)
	clerkLoginScopes     = []string{"offline_access", "user:org:read"}
)

type BuildSettings struct {
	Targets, ClientID, APIScope, Issuer, APIOrigin string
}

func (b BuildSettings) syncTargets() (keybundle.SyncTargets, error) {
	terminal, ok := map[string]string{"production": "https://terminal.tinfoil.sh", "development": "https://local.tinfoil.sh"}[b.Targets]
	if !ok {
		return keybundle.SyncTargets{}, fmt.Errorf("this build has an unknown target profile %q", b.Targets)
	}
	return keybundle.SyncTargets{Terminal: terminal, APIOrigin: b.APIOrigin,
		Callback: keySyncCallback, Completion: terminal + "/cli/complete"}, nil
}

func (b BuildSettings) scopes() ([]string, error) {
	if !clerkClientIDPattern.MatchString(b.ClientID) || !clerkScopePattern.MatchString(b.APIScope) || slices.Contains(clerkLoginScopes, b.APIScope) {
		return nil, errors.New("Clerk sign-in is not configured in this build (it needs the registered CLI OAuth client and API scope); use `tinfoil login --api-key` instead")
	}
	return append(slices.Clone(clerkLoginScopes), b.APIScope), nil
}

type Grant struct {
	Version      int    `json:"version"`
	Grant        string `json:"grant"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	UserID       string `json:"user_id"`
	Account      string `json:"account"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type SyncedDEK struct {
	Version   int                 `json:"version"`
	APIOrigin string              `json:"api_origin"`
	UserID    string              `json:"user_id"`
	DEKID     string              `json:"dek_id"`
	DEK       keybundle.Base64URL `json:"dek"`
}

// Lifecycle callbacks run under the credential lock and must not reacquire it.
type Lifecycle struct {
	CleanupResources func() error
	LoginCommitted   func() error
}

type Service struct {
	settings  BuildSettings
	store     *Store
	http      *http.Client
	version   string
	lifecycle Lifecycle
}

// New is lazy: credentials are accessed only by the requested operation.
func New(settings BuildSettings, store *Store, client *http.Client, version string, lifecycle Lifecycle) *Service {
	httpClient := http.Client{Timeout: requestTimeout}
	if client != nil {
		httpClient = *client
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Service{settings: settings, store: store, http: &httpClient, version: version, lifecycle: lifecycle}
}

func dekRecordName(apiOrigin, userID string) string {
	digest := sha256.Sum256([]byte(apiOrigin + "\x00" + userID))
	return "dek-" + hex.EncodeToString(digest[:])[:32]
}

func (s *Service) CurrentGrant() (*Grant, error) {
	var grant Grant
	found, err := s.store.read(loginRecordName, &grant)
	if err != nil || !found {
		return nil, err
	}
	if grant.Version != 1 || !keybundle.ValidID16(grant.Grant) || grant.Issuer != s.settings.Issuer || grant.ClientID != s.settings.ClientID ||
		!keybundle.ValidUserID(grant.UserID) || !keybundle.ValidAccount(grant.Account) || grant.AccessToken == "" {
		return nil, errors.New("the saved login belongs to another CLI build or is damaged; run `tinfoil login`")
	}
	return &grant, nil
}

func (s *Service) SyncedKey(login *Grant, userID string) (*SyncedDEK, error) {
	if login == nil || login.UserID != userID {
		return nil, nil
	}
	var dek SyncedDEK
	found, err := s.store.read(dekRecordName(s.settings.APIOrigin, userID), &dek)
	if err != nil || !found {
		return nil, err
	}
	if dek.Version != 1 || dek.APIOrigin != s.settings.APIOrigin || dek.UserID != userID || !keybundle.ValidID16(dek.DEKID) || len(dek.DEK) != 32 {
		return nil, errors.New("the synced key on this machine is damaged; run `tinfoil login --sync`")
	}
	return &dek, nil
}

// WhileSignedIn guards both the grant check and the operation against logout and
// replacement logins. The operation must not reacquire the credential lock.
func (s *Service) WhileSignedIn(login *Grant, write func() error) error {
	return s.store.withLock(func() error {
		current, err := s.CurrentGrant()
		if err != nil {
			return err
		}
		if login == nil || current == nil || current.Grant != login.Grant {
			return errors.New("you signed out while connecting; run `tinfoil login --sync`")
		}
		return write()
	})
}

func (s *Service) commitLogin(ctx context.Context, grant *Grant) error {
	return s.store.withLock(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var previous Grant
		if found, _ := s.store.read(loginRecordName, &previous); found && previous.UserID != grant.UserID {
			if err := s.removeLocalCredentials(&previous); err != nil {
				return err
			}
		}
		if err := s.store.write(loginRecordName, grant); err != nil {
			return err
		}
		if s.lifecycle.LoginCommitted != nil {
			return s.lifecycle.LoginCommitted()
		}
		return nil
	})
}

type TokenSource struct {
	service *Service
	grant   *Grant
}

func (s *Service) TokenSource(grant *Grant) *TokenSource {
	return &TokenSource{service: s, grant: grant}
}

func (s *TokenSource) Token(ctx context.Context) (string, error) {
	return s.service.accessToken(ctx, s.grant)
}

func (s *Service) accessToken(ctx context.Context, g *Grant) (string, error) {
	var token string
	err := s.store.withLock(func() error {
		current, err := s.CurrentGrant()
		if err != nil {
			return err
		}
		if g == nil || current == nil || current.Grant != g.Grant {
			return errors.New("this login has ended; run `tinfoil login`")
		}
		if time.Now().Unix() < current.ExpiresAt-accessTokenSlack {
			token = current.AccessToken
			return nil
		}
		scopes, err := s.settings.scopes()
		if err != nil {
			return err
		}
		tokens, err := s.clerkToken(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {current.RefreshToken}}, scopes)
		if err != nil {
			return fmt.Errorf("renewing your login failed; run `tinfoil login`: %w", err)
		}
		userID, account, err := s.clerkIdentity(ctx, tokens.AccessToken)
		if err != nil {
			return fmt.Errorf("checking the renewed login: %w", err)
		}
		if userID != current.UserID || account != current.Account {
			return errors.New("the renewed login belongs to a different account; run `tinfoil login`")
		}
		current.AccessToken, current.ExpiresAt = tokens.AccessToken, time.Now().Unix()+tokens.ExpiresIn
		if tokens.RefreshToken != "" {
			current.RefreshToken = tokens.RefreshToken
		}
		if err := s.store.write(loginRecordName, current); err != nil {
			return err
		}
		token = current.AccessToken
		return nil
	})
	return token, err
}

type LogoutResult struct {
	UserID          string
	Removed         bool
	RevocationError error
}

func (s *Service) Logout(ctx context.Context) (LogoutResult, error) {
	var result LogoutResult
	err := s.store.withLock(func() error {
		var grant Grant
		found, readErr := s.store.read(loginRecordName, &grant)
		if found && grant.RefreshToken != "" && grant.ClientID != "" {
			form := url.Values{"token": {grant.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {grant.ClientID}}
			_, result.RevocationError = s.clerkPost(ctx, "/oauth/token/revoke", form)
		}
		if !found {
			grant = Grant{}
		}
		if err := s.removeLocalCredentials(&grant); err != nil {
			return err
		}
		result.UserID, result.Removed = grant.UserID, found
		return readErr
	})
	return result, err
}

func (s *Service) removeLocalCredentials(grant *Grant) error {
	errs := []error{s.store.delete(loginRecordName)}
	if grant.UserID != "" {
		errs = append(errs, s.store.delete(dekRecordName(s.settings.APIOrigin, grant.UserID)))
	}
	files, _ := filepath.Glob(s.store.file("dek-*"))
	for _, file := range files {
		errs = append(errs, s.store.delete(strings.TrimSuffix(filepath.Base(file), ".json")))
	}
	if s.lifecycle.CleanupResources != nil {
		errs = append(errs, s.lifecycle.CleanupResources())
	}
	return errors.Join(errs...)
}

func randomB64U(n int) string {
	data := make([]byte, n)
	rand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data)
}
