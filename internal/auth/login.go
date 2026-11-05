package auth

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

const (
	loginListenPort   = "49152"
	loginCallbackHost = "localhost:" + loginListenPort
	oauthCallbackHost = "127.0.0.1:" + loginListenPort
	oauthDonePath     = "/oauth/done"
	loginDonePath     = "/callback/done"
	loginLifetime     = 10 * time.Minute
	loginCompleteWait = 30 * time.Second
)

type LoginProgress struct {
	Authorize func(string)
	SignedIn  func(userID, account string)
	SyncCode  func(string)
}

type LoginResult struct {
	Grant      *Grant
	KeysSynced bool
}

type loginCeremony struct {
	service  *Service
	ctx      context.Context
	scopes   []string
	state    string
	verifier string
	expires  int64
	syncKeys bool
	targets  keybundle.SyncTargets

	authorized chan struct{}
	grant      *Grant
	authErr    error
	private    *ecdh.PrivateKey
	request    keybundle.SyncRequest

	mu            sync.Mutex
	oauthConsumed bool
	consumed      bool
	finished      chan struct{}
	sent          chan struct{}
	err           error
}

func (s *Service) Login(ctx context.Context, syncKeys bool, progress LoginProgress) (LoginResult, error) {
	var result LoginResult
	scopes, err := s.settings.scopes()
	if err != nil {
		return result, err
	}
	var targets keybundle.SyncTargets
	if syncKeys {
		targets, err = s.settings.syncTargets()
		if err != nil {
			return result, err
		}
	}
	listeners, err := listenLoopback()
	if err != nil {
		return result, err
	}
	expires := time.Now().Add(loginLifetime)
	ctx, stop := context.WithDeadline(ctx, expires)
	defer stop()
	ceremony := &loginCeremony{service: s, ctx: ctx, scopes: scopes, state: randomB64U(32), verifier: randomB64U(32),
		expires: expires.Unix(), syncKeys: syncKeys, targets: targets,
		authorized: make(chan struct{}), finished: make(chan struct{}), sent: make(chan struct{})}
	server := &http.Server{Handler: ceremony, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	for _, listener := range listeners {
		go server.Serve(listener)
		defer listener.Close()
	}
	defer server.Close()

	if progress.Authorize != nil {
		progress.Authorize(s.authorizationURL(ceremony.state, ceremony.verifier, scopes))
	}
	select {
	case <-ceremony.authorized:
	case <-ctx.Done():
		select {
		case <-ceremony.authorized:
		default:
			return result, fmt.Errorf("sign-in did not complete: %w", context.Cause(ctx))
		}
	}
	if ceremony.authErr == nil {
		result.Grant = ceremony.grant
		if progress.SignedIn != nil {
			progress.SignedIn(ceremony.grant.UserID, ceremony.grant.Account)
		}
		if syncKeys && ceremony.private != nil && progress.SyncCode != nil {
			progress.SyncCode(keybundle.ConfirmationCode(keybundle.CanonicalRequest(ceremony.request, targets)))
		}
	}
	select {
	case <-ceremony.finished:
	case <-ctx.Done():
		select {
		case <-ceremony.finished:
		default:
			return result, fmt.Errorf("signed in, but key sync did not complete: %w; run `tinfoil login --sync` to try again", context.Cause(ctx))
		}
	}
	// Let the browser receive its clean completion page before closing the listener.
	select {
	case <-ceremony.sent:
	case <-ctx.Done():
	case <-time.After(loginCompleteWait):
	}
	shutdown, done := context.WithTimeout(context.Background(), loginCompleteWait)
	defer done()
	server.Shutdown(shutdown)
	if ceremony.authErr != nil {
		return result, ceremony.authErr
	}
	if ceremony.err != nil {
		return result, fmt.Errorf("signed in, but key sync failed: %w", ceremony.err)
	}
	result.KeysSynced = syncKeys
	return result, nil
}

func listenLoopback() ([]net.Listener, error) {
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", loginListenPort))
	if err != nil {
		return nil, fmt.Errorf("the sign-in callback port %s is unavailable (%w); close the program using it and retry", loginListenPort, err)
	}
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", loginListenPort))
	if err == nil {
		return []net.Listener{v4, v6}, nil
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		v4.Close()
		return nil, fmt.Errorf("the sign-in callback port %s is in use on [::1]; close the program using it and retry", loginListenPort)
	}
	return []net.Listener{v4}, nil
}

func (c *loginCeremony) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	host := loginCallbackHost
	if r.URL.Path == "/oauth/callback" || r.URL.Path == oauthDonePath {
		host = oauthCallbackHost
	}
	if r.Method != http.MethodGet || r.Host != host {
		loginPage(w, http.StatusBadRequest, "This is not a Tinfoil sign-in request.")
		return
	}
	switch r.URL.Path {
	case "/oauth/callback":
		c.oauthCallback(w, r)
	case oauthDonePath:
		select {
		case <-c.authorized:
		case <-r.Context().Done():
			return
		}
		if c.authErr == nil && c.syncKeys && c.private != nil {
			http.Redirect(w, r, keybundle.LaunchURL(c.request, c.targets), http.StatusSeeOther)
			return
		}
		c.done(w, r)
	case "/callback":
		c.keyCallback(w, r)
	case loginDonePath:
		c.done(w, r)
	default:
		loginPage(w, http.StatusNotFound, "Not found.")
	}
}

func (c *loginCeremony) oauthCallback(w http.ResponseWriter, r *http.Request) {
	code, failure, err := parseOAuthCallback(r.URL.RawQuery, c.state, c.service.settings.Issuer)
	if err != nil || c.ctx.Err() != nil || time.Now().Unix() >= c.expires {
		loginPage(w, http.StatusBadRequest, "This Clerk authorization reply is invalid or expired.")
		return
	}
	c.mu.Lock()
	consumed := c.oauthConsumed
	c.oauthConsumed = true
	c.mu.Unlock()
	if consumed {
		loginPage(w, http.StatusConflict, "This authorization reply was already used.")
		return
	}
	go c.authorize(code, failure)
	// Remove the authorization code from the browser URL before the exchange finishes.
	http.Redirect(w, r, oauthDonePath, http.StatusSeeOther)
}

func (c *loginCeremony) authorize(code, failure string) {
	defer close(c.authorized)
	if failure != "" {
		c.authErr = fmt.Errorf("Clerk authorization failed: %s", failure)
	} else {
		c.grant, c.authErr = c.redeem(code)
	}
	if c.authErr == nil && c.syncKeys {
		c.private, c.err = ecdh.X25519().GenerateKey(rand.Reader)
		if c.err == nil {
			c.request = keybundle.SyncRequest{HPKEPublicKey: c.private.PublicKey().Bytes(), Request: randomB64U(32),
				UserID: c.grant.UserID, Account: c.grant.Account, Expires: c.expires}
		}
	}
	if c.authErr != nil || !c.syncKeys || c.private == nil {
		close(c.finished)
	}
}

func (c *loginCeremony) keyCallback(w http.ResponseWriter, r *http.Request) {
	select {
	case <-c.authorized:
	default:
		loginPage(w, http.StatusBadRequest, "Sign in with Clerk before syncing keys.")
		return
	}
	if c.authErr != nil || !c.syncKeys || c.private == nil {
		loginPage(w, http.StatusBadRequest, "No key sync was requested.")
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	payload := values["payload"]
	if err != nil || len(r.URL.RawQuery) > len("payload=")+keybundle.MaxKeySyncPayloadChars || len(values) != 1 || len(payload) != 1 {
		loginPage(w, http.StatusBadRequest, "The key-sync reply is malformed.")
		return
	}
	envelope, err := keybundle.OpenSyncEnvelope(c.private, c.request, c.targets, payload[0])
	if err != nil || c.ctx.Err() != nil || time.Now().Unix() >= c.request.Expires {
		if envelope != nil {
			clear(envelope.DEK)
		}
		loginPage(w, http.StatusBadRequest, "The key-sync reply does not match this terminal's request or has expired.")
		return
	}
	c.mu.Lock()
	consumed := c.consumed
	c.consumed = true
	c.mu.Unlock()
	if consumed {
		clear(envelope.DEK)
		loginPage(w, http.StatusConflict, "This key-sync reply was already used.")
		return
	}
	go func() {
		defer close(c.finished)
		defer clear(envelope.DEK)
		c.err = c.saveSyncedKey(envelope)
	}()
	http.Redirect(w, r, loginDonePath, http.StatusSeeOther)
}

func (c *loginCeremony) done(w http.ResponseWriter, r *http.Request) {
	select {
	case <-c.finished:
	case <-r.Context().Done():
		return
	}
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		select {
		case <-c.sent:
		default:
			close(c.sent)
		}
	}()
	if c.authErr != nil {
		loginPage(w, http.StatusBadRequest, "Sign-in failed. Return to your terminal for details.")
		return
	}
	if c.err != nil {
		loginPage(w, http.StatusBadRequest, "You are signed in, but keys were not synced. Return to your terminal for details.")
		return
	}
	if c.syncKeys {
		http.Redirect(w, r, keybundle.CompletionURL(c.targets, c.request.Request, c.grant.UserID, c.grant.Account), http.StatusSeeOther)
		return
	}
	loginPage(w, http.StatusOK, "You are signed in to the Tinfoil CLI. You can close this tab and return to your terminal.")
}

func loginPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><title>Tinfoil CLI</title><p>%s</p>", html.EscapeString(message))
}

func (c *loginCeremony) redeem(code string) (*Grant, error) {
	tokens, err := c.service.clerkToken(c.ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {oauthCallback}, "code_verifier": {c.verifier}}, c.scopes)
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		return nil, errors.New("Clerk granted no refresh token")
	}
	userID, account, err := c.service.clerkIdentity(c.ctx, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("checking the new login: %w", err)
	}
	grant := &Grant{Version: 1, Grant: randomB64U(16), Issuer: c.service.settings.Issuer, ClientID: c.service.settings.ClientID,
		UserID: userID, Account: account, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		ExpiresAt: time.Now().Unix() + tokens.ExpiresIn}
	if err := c.service.commitLogin(c.ctx, grant); err != nil {
		return nil, err
	}
	return grant, nil
}

func (c *loginCeremony) saveSyncedKey(envelope *keybundle.SyncEnvelope) error {
	client := controlplane.New(c.targets.APIOrigin, c.service.version, c.service.http, c.service.TokenSource(c.grant))
	state, err := client.KeyState(c.ctx)
	if err != nil {
		return err
	}
	if state.DEKID == nil || *state.DEKID != envelope.DEKID || state.EncryptedMK == nil {
		return errors.New("the synced key does not match your current key bundle")
	}
	if _, err := keybundle.Open(*state.EncryptedMK, envelope.DEK, keybundle.Context{APIOrigin: c.targets.APIOrigin, UserID: c.grant.UserID, DEKID: envelope.DEKID}); err != nil {
		return fmt.Errorf("checking the synced key: %w", err)
	}
	dek := &SyncedDEK{Version: 1, APIOrigin: c.targets.APIOrigin, UserID: c.grant.UserID, DEKID: envelope.DEKID, DEK: envelope.DEK}
	return c.service.WhileSignedIn(c.grant, func() error {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		return c.service.store.write(dekRecordName(dek.APIOrigin, dek.UserID), dek)
	})
}
