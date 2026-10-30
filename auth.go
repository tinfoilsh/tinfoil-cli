package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(loginCmd, logoutCmd, whoamiCmd)
	for _, cmd := range []*cobra.Command{loginCmd, logoutCmd, whoamiCmd} {
		cmd.SilenceUsage = true
	}
	loginCmd.Flags().String("url", "", "Controlplane URL for --api-key (default https://api.tinfoil.sh)")
	loginCmd.Flags().String("api-key", "", "Sign in with an admin API key (admin_...) instead of the browser")
	loginCmd.Flags().Bool("sync", false, "Sync your sandbox keys to this machine")
	loginCmd.Flags().Bool("no-sync", false, "Sign in without syncing your sandbox keys")
}

const (
	loginListenPort    = "49152"
	loginCallbackHost  = "localhost:" + loginListenPort
	oauthCallbackHost  = "127.0.0.1:" + loginListenPort
	oauthDonePath      = "/oauth/done"
	loginDonePath      = "/callback/done"
	loginLifetime      = 10 * time.Minute
	loginCompleteWait  = 30 * time.Second
	accessTokenSlack   = 60
	maxOAuthReplyBytes = 64 << 10
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in to Tinfoil in your browser, or with an admin API key",
	Long: `Sign in directly with Clerk in your browser using PKCE. Clerk returns to the
CLI at http://127.0.0.1:49152/oauth/callback, and the CLI saves your login.
With --sync, terminal.tinfoil.sh then asks you to confirm a code and unlock your
sandbox keys. It sends their key encrypted to this machine, which stores it in
the OS credential service or, without one, in ~/.tinfoil/credentials (mode 0600).
Cancelling key sync keeps your login. Without sync, terminal.tinfoil.sh is not used.

With --api-key, store an admin API key (Settings → API Keys → Admin keys) at
~/.tinfoil/config.json (mode 0600) for automation. The TINFOIL_ADMIN_KEY and
TINFOIL_CONTROLPLANE_URL environment variables override saved admin keys.
TINFOIL_API_KEY is also honored when it holds an admin_ key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		urlFlag, _ := cmd.Flags().GetString("url")
		keyFlag, _ := cmd.Flags().GetString("api-key")
		if keyFlag == "" && urlFlag == "" {
			sync, err := loginSyncChoice(cmd)
			if err != nil {
				return err
			}
			return clerkLogin(cmd, sync)
		}

		cfg, _, err := loadConfig()
		if err != nil {
			return err
		}

		if urlFlag != "" {
			cfg.ControlplaneURL = strings.TrimRight(urlFlag, "/")
		}
		if cfg.ControlplaneURL == "" {
			cfg.ControlplaneURL = defaultControlplaneURL
		}
		if err := validateControlplaneURL(cfg.ControlplaneURL); err != nil {
			return err
		}

		key := strings.TrimSpace(keyFlag)
		if key == "" {
			key, err = promptSecret("api key", fmt.Sprintf("Enter admin API key for %s: ", cfg.ControlplaneURL))
			if err != nil {
				return err
			}
		}
		if key == "" {
			return errors.New("api key is required")
		}
		if !strings.HasPrefix(key, adminKeyPrefix) {
			return fmt.Errorf("expected an admin key (prefix %s), got %q", adminKeyPrefix, redactKey(key))
		}

		cfg.APIKey = key

		identity, err := authenticatedContext(cfg)
		if err != nil {
			return fmt.Errorf("credential check failed: %w", err)
		}

		path, err := saveConfig(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("Credentials saved to %s\n", path)
		printAuthContext("Saved credential", cfg, "file: "+path, identity)
		effective, _, err := loadConfig()
		if err != nil {
			return err
		}
		if credentialEnvSource() != "" || effective.ControlplaneURL != cfg.ControlplaneURL {
			fmt.Fprintln(os.Stderr, "WARNING: environment overrides remain active; the saved credential is not necessarily the effective login.")
			identity, err = authenticatedContext(effective)
			if err != nil {
				return fmt.Errorf("credentials saved, but effective environment login could not be verified: %w", err)
			}
		}
		printAuthContext("Effective login", effective, credentialSource(), identity)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out and remove stored Tinfoil credentials and synced keys",
	Long:  "Revoke the Clerk login when possible, then remove its tokens, the synced key, and the SSH keys this CLI exported from synced resources, even if revocation fails. Your own SSH keys and locally generated resource keys stay.",
	RunE: func(cmd *cobra.Command, args []string) error {
		clerkErr := clerkLogout(cmd.OutOrStdout())
		path, removed, err := deleteConfig()
		switch {
		case err != nil:
		case !removed:
			fmt.Printf("No saved admin key to remove (%s did not exist)\n", path)
		default:
			fmt.Printf("Removed %s\n", path)
		}
		if source := credentialEnvSource(); source != "" {
			fmt.Fprintf(os.Stderr, "WARNING: %s is still active; logout removes only the saved file. Unset %s and any admin key in %s to stop using environment credentials.\n", source, envAdminKey, envAPIKey)
		}
		return errors.Join(clerkErr, err)
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current login and organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireAuth()
		if err != nil {
			return err
		}

		identity, err := authenticatedContext(cfg)
		if err != nil {
			return fmt.Errorf("verifying credentials: %w", err)
		}
		source := credentialSource()
		if cfg.login != nil {
			source = "Clerk login"
			if dek, err := syncedKey(cfg.login, identity.UserID); err != nil || dek == nil {
				source += " (sandbox keys not synced)"
			}
		}
		printAuthContext("Effective login", cfg, source, identity)
		return nil
	},
}

func promptSecret(what, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		return strings.TrimSpace(string(raw)), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		return "", fmt.Errorf("no %s provided", what)
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func redactKey(key string) string {
	if len(key) <= 12 {
		return "***"
	}
	return key[:8] + "…" + key[len(key)-4:]
}

type authContext struct {
	ContextType  string `json:"context_type"`
	Organization *struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
	} `json:"organization"`
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
}

func authenticatedContext(cfg cliConfig) (authContext, error) {
	identity, err := clientContext(context.Background(), newCPClient(cfg))
	// A grant keeps the account it was issued for; switching requires a new login.
	if err == nil && cfg.login != nil && (identity.UserID != cfg.login.UserID || identity.account() != cfg.login.Account) {
		err = errors.New("the API reports a different account than this login; run `tinfoil login` to choose an account")
	}
	return identity, err
}

func clientContext(ctx context.Context, client *cpClient) (authContext, error) {
	var identity authContext
	if _, err := client.doContext(ctx, "GET", "/api/auth/context", nil, nil, nil, &identity); err != nil {
		return identity, err
	}
	if identity.UserID == "" || identity.ContextType != "personal" && identity.ContextType != "organization" ||
		identity.ContextType == "organization" && (identity.Organization == nil || identity.Organization.ID == "") ||
		identity.ContextType == "personal" && identity.Organization != nil {
		return identity, fmt.Errorf("invalid authenticated context response")
	}
	return identity, nil
}

// account is the key-bundle binding form: the organization ID or "personal".
func (a authContext) account() string {
	if a.Organization != nil {
		return a.Organization.ID
	}
	return "personal"
}

func loginSyncChoice(cmd *cobra.Command) (bool, error) {
	sync, _ := cmd.Flags().GetBool("sync")
	noSync, _ := cmd.Flags().GetBool("no-sync")
	if sync && noSync {
		return false, errors.New("choose either --sync or --no-sync")
	}
	if sync || noSync || !term.IsTerminal(int(os.Stdin.Fd())) {
		return sync, nil
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Sync your sandbox keys to this machine? [y/N] ")
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func randomB64U(n int) string {
	data := make([]byte, n)
	rand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data)
}

// loginCeremony owns direct OAuth login and the optional subsequent key transfer.
// The PKCE verifier never leaves CLI except for the exchange with Clerk. The
// terminal receives only a fresh key-sync request after the grant is committed.
type loginCeremony struct {
	ctx      context.Context
	scopes   []string
	state    string
	verifier string
	expires  int64
	syncKeys bool
	targets  keySyncTargets

	authorized chan struct{}
	grant      *clerkGrant
	authErr    error
	private    *ecdh.PrivateKey
	request    keySyncRequest

	mu            sync.Mutex
	oauthConsumed bool
	consumed      bool
	finished      chan struct{}
	sent          chan struct{}
	err           error
}

func clerkLogin(cmd *cobra.Command, syncKeys bool) error {
	scopes, err := clerkScopes()
	if err != nil {
		return err
	}
	var targets keySyncTargets
	if syncKeys {
		targets, err = fixedKeySyncTargets()
		if err != nil {
			return err
		}
	}
	// Own the fixed port before opening Clerk, including when key sync is declined.
	listeners, err := listenLoopback()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	expires := time.Now().Add(loginLifetime)
	ctx, stop := context.WithDeadline(ctx, expires)
	defer stop()
	ceremony := &loginCeremony{ctx: ctx, scopes: scopes, state: randomB64U(32), verifier: randomB64U(32),
		expires: expires.Unix(), syncKeys: syncKeys, targets: targets,
		authorized: make(chan struct{}), finished: make(chan struct{}), sent: make(chan struct{})}
	server := &http.Server{Handler: ceremony, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	for _, listener := range listeners {
		go server.Serve(listener)
		defer listener.Close()
	}
	defer server.Close()

	launch := clerkAuthorizationURL(ceremony.state, ceremony.verifier, scopes)
	fmt.Fprintf(cmd.ErrOrStderr(), "Opening Clerk sign-in. If no browser opens, visit:\n\n  %s\n\nWaiting for sign-in (Ctrl-C cancels)...\n", launch)
	go func() {
		if err := openBrowser(launch); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Could not open your browser: %v\n", err)
		}
	}()
	select {
	case <-ceremony.authorized:
	case <-ctx.Done():
		select {
		case <-ceremony.authorized:
		default:
			return fmt.Errorf("sign-in did not complete: %w", context.Cause(ctx))
		}
	}
	if ceremony.authErr == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Signed in as %s (account %s).\n", ceremony.grant.UserID, ceremony.grant.Account)
		if syncKeys && ceremony.private != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nEnter this code in the browser tab that just opened:\n\n    %s\n\nCtrl-C skips key sync and keeps your login.\n",
				confirmationCode(canonicalKeySyncRequest(ceremony.request, targets)))
		}
	}
	select {
	case <-ceremony.finished:
	case <-ctx.Done():
		select {
		case <-ceremony.finished:
		default:
			return fmt.Errorf("signed in, but key sync did not complete: %w; run `tinfoil login --sync` to try again", context.Cause(ctx))
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
		return ceremony.authErr
	}
	if ceremony.err != nil {
		return fmt.Errorf("signed in, but key sync failed: %w", ceremony.err)
	}
	if syncKeys {
		fmt.Fprintln(cmd.OutOrStdout(), "Sandbox keys synced to this machine.")
	}
	return nil
}

func clerkAuthorizationURL(state, verifier string, scopes []string) string {
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {clerkCLIClientID}, "redirect_uri": {oauthCallback},
		"scope": {strings.Join(scopes, " ")}, "state": {state}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "resource": {fixedAPIOrigin}}
	return clerkIssuer + "/oauth/authorize?" + query.Encode()
}

// listenLoopback binds the fixed callback port on loopback only: IPv4, plus IPv6 where the host has it.
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
			http.Redirect(w, r, keySyncLaunchURL(c.request, c.targets), http.StatusSeeOther)
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

// A single configured issuer supplies code/state. Validate RFC 9207's issuer
// parameter when supplied; Clerk's ordinary code/state response is also valid.
func parseOAuthCallback(query, state string) (code, failure string, err error) {
	bad := errors.New("the Clerk authorization reply is malformed or belongs to another sign-in")
	values, parseErr := url.ParseQuery(query)
	if parseErr != nil || len(query) > 8192 || values.Get("state") != state {
		return "", "", bad
	}
	for name, value := range values {
		if !slices.Contains([]string{"code", "state", "iss", "error", "error_description", "error_uri"}, name) || len(value) != 1 || len(value[0]) > 2048 {
			return "", "", bad
		}
	}
	if issuer, present := values["iss"]; present && issuer[0] != clerkIssuer {
		return "", "", bad
	}
	code, failure = values.Get("code"), values.Get("error")
	if (code == "") == (failure == "") ||
		(code != "" && (values.Has("error") || values.Has("error_description") || values.Has("error_uri") || !printableASCII(code))) ||
		(failure != "" && (values.Has("code") || !printableASCII(failure))) {
		return "", "", bad
	}
	return code, failure, nil
}

func (c *loginCeremony) oauthCallback(w http.ResponseWriter, r *http.Request) {
	code, failure, err := parseOAuthCallback(r.URL.RawQuery, c.state)
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
			c.request = keySyncRequest{HPKEPublicKey: c.private.PublicKey().Bytes(), Request: randomB64U(32),
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
	if err != nil || len(r.URL.RawQuery) > len("payload=")+maxKeySyncPayloadChars || len(values) != 1 || len(payload) != 1 {
		loginPage(w, http.StatusBadRequest, "The key-sync reply is malformed.")
		return
	}
	envelope, err := openKeySyncEnvelope(c.private, c.request, c.targets, payload[0])
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
		http.Redirect(w, r, keySyncCompletionURL(c.targets, c.request.Request, c.grant.UserID, c.grant.Account), http.StatusSeeOther)
		return
	}
	loginPage(w, http.StatusOK, "You are signed in to the Tinfoil CLI. You can close this tab and return to your terminal.")
}

func loginPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><title>Tinfoil CLI</title><p>%s</p>", html.EscapeString(message))
}

// redeem authenticates directly with Clerk and commits the grant independently of key sync.
func (c *loginCeremony) redeem(code string) (*clerkGrant, error) {
	tokens, err := clerkToken(c.ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {oauthCallback}, "code_verifier": {c.verifier}}, c.scopes)
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		return nil, errors.New("Clerk granted no refresh token")
	}
	userID, account, err := clerkIdentity(c.ctx, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("checking the new login: %w", err)
	}
	grant := &clerkGrant{Version: 1, Grant: randomB64U(16), Issuer: clerkIssuer, ClientID: clerkCLIClientID,
		UserID: userID, Account: account, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		ExpiresAt: time.Now().Unix() + tokens.ExpiresIn}
	if err := commitLogin(c.ctx, grant); err != nil {
		return nil, err
	}
	return grant, nil
}

func (c *loginCeremony) saveSyncedKey(envelope *keySyncEnvelope) error {
	cfg := cliConfig{ControlplaneURL: c.targets.APIOrigin, login: c.grant}
	state, err := fetchKeyState(c.ctx, newCPClient(cfg))
	if err != nil {
		return err
	}
	if state.DEKID == nil || *state.DEKID != envelope.DEKID || state.EncryptedMK == nil {
		return errors.New("the synced key does not match your current key bundle")
	}
	if _, err := openMK(*state.EncryptedMK, envelope.DEK, mkContext{c.targets.APIOrigin, c.grant.UserID, envelope.DEKID}); err != nil {
		return fmt.Errorf("checking the synced key: %w", err)
	}
	dek := &syncedDEK{Version: 1, APIOrigin: c.targets.APIOrigin, UserID: c.grant.UserID, DEKID: envelope.DEKID, DEK: envelope.DEK}
	return whileSignedIn(c.grant, func() error {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		return writeCredential(dekRecordName(dek.APIOrigin, dek.UserID), dek)
	})
}

func commitLogin(ctx context.Context, grant *clerkGrant) error {
	return withCredentialLock(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var previous clerkGrant
		if found, _ := readCredential(loginRecordName, &previous); found && previous.UserID != grant.UserID {
			if err := removeLocalCredentials(&previous); err != nil {
				return err
			}
		}
		if err := writeCredential(loginRecordName, grant); err != nil {
			return err
		}
		// The latest interactive login wins over a previously saved admin key.
		cfg, path, err := loadConfig()
		if err == nil && cfg.APIKey != "" && envAdminAPIKey() == "" {
			if _, statErr := os.Stat(path); statErr == nil {
				_, _, err = deleteConfig()
			}
		}
		return err
	})
}

type clerkTokens struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	Scope        *string `json:"scope"`
}

// clerkToken calls the fixed Clerk token endpoint for this build's public client.
func clerkToken(ctx context.Context, form url.Values, scopes []string) (*clerkTokens, error) {
	form.Set("client_id", clerkCLIClientID)
	form.Set("resource", fixedAPIOrigin)
	reply, err := clerkPost(ctx, "/oauth/token", form)
	if err != nil {
		return nil, err
	}
	var tokens clerkTokens
	if err := json.Unmarshal(reply, &tokens); err != nil || tokens.AccessToken == "" || !strings.EqualFold(tokens.TokenType, "bearer") ||
		tokens.ExpiresIn <= 0 || tokens.ExpiresIn > maxSafeInteger {
		return nil, errors.New("Clerk returned an invalid token response")
	}
	// An omitted scope means the requested one (RFC 6749 section 5.1).
	if tokens.Scope != nil {
		granted := strings.Fields(*tokens.Scope)
		for _, scope := range scopes {
			if !slices.Contains(granted, scope) {
				return nil, fmt.Errorf("Clerk did not grant the %q scope this CLI requires", scope)
			}
		}
	}
	return &tokens, nil
}

// clerkIdentity asks the issuer to authenticate the access token and resolve its
// granted account. Login and renewal do not depend on the resource API accepting it.
func clerkIdentity(ctx context.Context, accessToken string) (userID, account string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clerkIssuer+"/oauth/userinfo", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	reply, err := clerkRequest(req)
	if err != nil {
		return "", "", err
	}
	var identity struct {
		Subject        string `json:"sub"`
		UserID         string `json:"user_id"`
		OrganizationID string `json:"org_id"`
	}
	if err := json.Unmarshal(reply, &identity); err != nil || !userIDPattern.MatchString(identity.Subject) ||
		(identity.UserID != "" && identity.UserID != identity.Subject) ||
		(identity.OrganizationID != "" && (!strings.HasPrefix(identity.OrganizationID, "org_") || !accountPattern.MatchString(identity.OrganizationID))) {
		return "", "", errors.New("Clerk returned an invalid login identity")
	}
	account = identity.OrganizationID
	if account == "" {
		account = "personal"
	}
	return identity.Subject, account, nil
}

func clerkPost(ctx context.Context, path string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, clerkIssuer+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return clerkRequest(req)
}

func clerkRequest(req *http.Request) ([]byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), time.Minute)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Clerk: %w", err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthReplyBytes+1))
	if err != nil || len(reply) > maxOAuthReplyBytes {
		return nil, errors.Join(errors.New("Clerk reply is unreadable or too large"), err)
	}
	if resp.StatusCode != http.StatusOK {
		var oauth struct {
			Error string `json:"error"`
		}
		json.Unmarshal(reply, &oauth)
		return nil, fmt.Errorf("Clerk %s: %d %s", req.URL.Path, resp.StatusCode, oauth.Error)
	}
	return reply, nil
}

// accessToken returns the current access token of this login under the credential
// lock, renewing it when needed. The loaded grant only names the login: after logout or
// a new login, no cached token is admitted.
func (g *clerkGrant) accessToken(ctx context.Context) (string, error) {
	var token string
	err := withCredentialLock(func() error {
		current, err := currentGrant()
		if err != nil {
			return err
		}
		if current == nil || current.Grant != g.Grant {
			return errors.New("this login has ended; run `tinfoil login`")
		}
		if time.Now().Unix() < current.ExpiresAt-accessTokenSlack {
			token = current.AccessToken
			return nil
		}
		scopes, err := clerkScopes()
		if err != nil {
			return err
		}
		tokens, err := clerkToken(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {current.RefreshToken}}, scopes)
		if err != nil {
			return fmt.Errorf("renewing your login failed; run `tinfoil login`: %w", err)
		}
		// Renewal never moves the grant to another user or account.
		userID, account, err := clerkIdentity(ctx, tokens.AccessToken)
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
		if err := writeCredential(loginRecordName, current); err != nil {
			return err
		}
		token = current.AccessToken
		return nil
	})
	return token, err
}

// clerkLogout revokes the refresh token when possible and always removes local credentials.
func clerkLogout(out io.Writer) error {
	return withCredentialLock(func() error {
		var grant clerkGrant
		found, readErr := readCredential(loginRecordName, &grant)
		if found && grant.RefreshToken != "" && grant.ClientID != "" {
			form := url.Values{"token": {grant.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {grant.ClientID}}
			if _, err := clerkPost(context.Background(), "/oauth/token/revoke", form); err != nil {
				fmt.Fprintf(out, "Could not revoke the Clerk login (%v); removing it locally anyway.\n", err)
			}
		}
		if !found {
			grant = clerkGrant{}
		}
		if err := removeLocalCredentials(&grant); err != nil {
			return err
		}
		if found {
			fmt.Fprintf(out, "Signed out %s and removed synced keys from this machine.\n", grant.UserID)
		}
		return readErr
	})
}

// removeLocalCredentials deletes the login, synced keys and SSH keys exported from synced resources.
func removeLocalCredentials(grant *clerkGrant) error {
	errs := []error{deleteCredential(loginRecordName)}
	if grant.UserID != "" {
		errs = append(errs, deleteCredential(dekRecordName(fixedAPIOrigin, grant.UserID)))
	}
	if pattern, err := credentialFile("dek-*"); err == nil {
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			errs = append(errs, deleteCredential(strings.TrimSuffix(filepath.Base(file), ".json")))
		}
	}
	return errors.Join(append(errs, removeExportedKeys())...)
}

func credentialEnvSource() string {
	if strings.TrimSpace(os.Getenv(envAdminKey)) != "" {
		return envAdminKey
	}
	if strings.HasPrefix(strings.TrimSpace(os.Getenv(envAPIKey)), adminKeyPrefix) {
		return envAPIKey
	}
	return ""
}

func credentialSource() string {
	if source := credentialEnvSource(); source != "" {
		return source
	}
	path, err := configPath()
	if err != nil {
		return "saved file (path unavailable)"
	}
	return "file: " + path
}

func printAuthContext(label string, cfg cliConfig, source string, identity authContext) {
	fmt.Printf("%s:\n", label)
	fmt.Printf("  Controlplane: %s\n  Credential: %s\n", cfg.ControlplaneURL, source)
	if cfg.APIKey != "" {
		fmt.Printf("  API key: %s\n", redactKey(cfg.APIKey))
	}
	fmt.Printf("  Context: %s\n", identity.ContextType)
	if identity.Organization != nil {
		fmt.Printf("  Organization ID: %s\n", identity.Organization.ID)
		if identity.Organization.Name != "" {
			fmt.Printf("  Organization name: %s\n", identity.Organization.Name)
		}
	}
	fmt.Printf("  User ID: %s\n", identity.UserID)
}
