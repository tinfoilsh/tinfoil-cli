package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

const (
	maxOAuthReplyBytes = 64 << 10
	requestTimeout     = time.Minute
)

func (s *Service) authorizationURL(state, verifier string, scopes []string) string {
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {s.settings.ClientID}, "redirect_uri": {oauthCallback},
		"scope": {strings.Join(scopes, " ")}, "state": {state}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "resource": {s.settings.APIOrigin}}
	return s.settings.Issuer + "/oauth/authorize?" + query.Encode()
}

func parseOAuthCallback(query, state, issuer string) (code, failure string, err error) {
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
	if replyIssuer, present := values["iss"]; present && replyIssuer[0] != issuer {
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

func printableASCII(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

type clerkTokens struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	Scope        *string `json:"scope"`
}

func (s *Service) clerkToken(ctx context.Context, form url.Values, scopes []string) (*clerkTokens, error) {
	form.Set("client_id", s.settings.ClientID)
	form.Set("resource", s.settings.APIOrigin)
	reply, err := s.clerkPost(ctx, "/oauth/token", form)
	if err != nil {
		return nil, err
	}
	var tokens clerkTokens
	if err := json.Unmarshal(reply, &tokens); err != nil || tokens.AccessToken == "" || !strings.EqualFold(tokens.TokenType, "bearer") ||
		tokens.ExpiresIn <= 0 || tokens.ExpiresIn > keybundle.MaxSafeInteger {
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

func (s *Service) clerkIdentity(ctx context.Context, accessToken string) (userID, account string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.settings.Issuer+"/oauth/userinfo", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	reply, err := s.clerkRequest(req)
	if err != nil {
		return "", "", err
	}
	var identity struct {
		Subject        string `json:"sub"`
		UserID         string `json:"user_id"`
		OrganizationID string `json:"org_id"`
	}
	if err := json.Unmarshal(reply, &identity); err != nil || !keybundle.ValidUserID(identity.Subject) ||
		(identity.UserID != "" && identity.UserID != identity.Subject) ||
		(identity.OrganizationID != "" && (!strings.HasPrefix(identity.OrganizationID, "org_") || !keybundle.ValidAccount(identity.OrganizationID))) {
		return "", "", errors.New("Clerk returned an invalid login identity")
	}
	account = identity.OrganizationID
	if account == "" {
		account = "personal"
	}
	return identity.Subject, account, nil
}

func (s *Service) clerkPost(ctx context.Context, path string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.settings.Issuer+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.clerkRequest(req)
}

func (s *Service) clerkRequest(req *http.Request) ([]byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), requestTimeout)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
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
