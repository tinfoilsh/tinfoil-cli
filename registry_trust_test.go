package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func enrollmentFixture(t *testing.T) registryEnrollment {
	t.Helper()
	t.Setenv(envKnownConfigs, filepath.Join(t.TempDir(), "trust.json"))
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	t.Setenv(envCPURL, defaultControlplaneURL)
	return registryEnrollment{ControlplaneURL: defaultControlplaneURL, AccountID: "org_acme", Label: "Acme", Namespaces: []string{"/acme"}, Scope: configendorsement.ScopePrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"}
}

func TestRegistryEnrollmentRequiresExplicitAcceptanceAndReplacement(t *testing.T) {
	entry := enrollmentFixture(t)
	var output bytes.Buffer
	require.NoError(t, acceptRegistry(strings.NewReader("no\n"), &output, entry, false))
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Empty(t, policy.Registries)
	require.NoError(t, acceptRegistry(strings.NewReader("yes\n"), &output, entry, false))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []registryEnrollment{entry}, policy.Registries)
	changed := entry
	changed.Scope = configendorsement.ScopePrefix + "ffffffffffffffffffffffffffffffff"
	require.NoError(t, acceptRegistry(strings.NewReader("\n"), &output, changed, false))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, entry.Scope, policy.Registries[0].Scope)
	require.NoError(t, acceptRegistry(strings.NewReader("yes\n"), &output, changed, false))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, changed.Scope, policy.Registries[0].Scope)
	require.Len(t, policy.Registries, 1)
}

func TestScopeCommandsKeepPersonalAndOrganizationApprovalsSeparate(t *testing.T) {
	entry := enrollmentFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/context":
			json.NewEncoder(w).Encode(map[string]any{"context_type": "organization", "user_id": "user_owner", "organization": map[string]string{"id": entry.AccountID, "name": entry.Label}})
		case registryEnrollmentPath:
			json.NewEncoder(w).Encode(registryAccount{OwnerKind: "organization", Namespaces: entry.Namespaces, Scope: entry.Scope})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_fixture")
	personal := entry
	personal.AccountID, personal.Namespaces, personal.Scope = "user_owner", []string{"/user-personal"}, configendorsement.ScopePrefix+strings.Repeat("f", 32)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, personal, true))
	require.NoError(t, executeLifecycleCLI(t, "trust", "scope", "add", "--scope", entry.Scope))
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Len(t, policy.Registries, 2)
	require.NoError(t, executeLifecycleCLI(t, "trust", "scope", "remove", entry.AccountID))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []registryEnrollment{personal}, policy.Registries)
}

func TestPublicRegistryPolicySurvivesSSHProxyCommand(t *testing.T) {
	previous := publicRegistry
	publicRegistry = true
	t.Cleanup(func() { publicRegistry = previous })
	command, err := proxyCommand(&tunnelTarget{host: "app.example.com", repo: "acme/app"}, defaultSSHPort)
	require.NoError(t, err)
	require.Contains(t, command, "'--public-registry'")
}

func TestRegistryEnrollmentRefusesRedirects(t *testing.T) {
	entry := enrollmentFixture(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/different-account", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	cmd := &cobra.Command{}
	err := enrollRegistry(cmd, cliConfig{ControlplaneURL: server.URL, APIKey: "admin_fixture"}, authContext{}, entry.Scope, false)
	require.ErrorContains(t, err, "refusing a controlplane redirect")
	require.Equal(t, 1, requests)
}

func TestRegistryEnrollmentSelectsOnlyItsNamespacesAndControlPlane(t *testing.T) {
	entry := enrollmentFixture(t)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, entry, true))
	options, err := registrySigningOptions("acme/app@v1")
	require.NoError(t, err)
	v, err := verify.NewVerifier(options...)
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	doc, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(doc, nonce, "acme/app")
	require.ErrorContains(t, err, "configured trust requires")
	options, err = registrySigningOptions("other/app")
	require.NoError(t, err)
	require.Empty(t, options)
	t.Setenv(envCPURL, "https://another-controlplane.example")
	options, err = registrySigningOptions("acme/app")
	require.NoError(t, err)
	require.Empty(t, options)
	t.Setenv(envCPURL, defaultControlplaneURL)
	publicRegistry = true
	t.Cleanup(func() { publicRegistry = false })
	options, err = registrySigningOptions("acme/app")
	require.NoError(t, err)
	require.Empty(t, options)
	require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte("invalid"), 0600))
	_, err = registrySigningOptions("acme/app")
	require.ErrorContains(t, err, "malformed")
}

func TestRegistryEnrollmentRejectsMalformedAndConflictingPolicies(t *testing.T) {
	entry := enrollmentFixture(t)
	for _, scope := range []string{"", "not a scope", entry.Scope + "/", entry.Scope + "\n", strings.Replace(entry.Scope, "9c4a", "9C4A", 1), strings.Replace(entry.Scope, "9c4a", "9c-4a", 1)} {
		invalid := entry
		invalid.Scope = scope
		require.Error(t, validateRegistryEnrollments([]registryEnrollment{invalid}))
	}
	other := entry
	other.AccountID = "org_other"
	require.ErrorContains(t, validateRegistryEnrollments([]registryEnrollment{entry, other}), "conflicting")
	other.ControlplaneURL = "https://another-controlplane.example"
	require.NoError(t, validateRegistryEnrollments([]registryEnrollment{entry, other}))
}

func TestClerkRegistryEnrollmentUsesTheAuthenticatedAPIOrigin(t *testing.T) {
	entry := enrollmentFixture(t)
	useTestClerk(t, entry.ControlplaneURL)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, entry, true))
	require.NoError(t, writeCredential(loginRecordName, &clerkGrant{
		Version: 1, Grant: randomB64U(16), Issuer: clerkIssuer, ClientID: clerkCLIClientID,
		UserID: "user_owner", Account: entry.AccountID, AccessToken: "fixture-access",
	}))
	t.Setenv(envCPURL, "https://another-controlplane.example")
	options, err := registrySigningOptions("acme/app")
	require.NoError(t, err)
	require.Len(t, options, 1, "a URL override cannot bypass the Clerk account's enrolled scope")
	t.Setenv(envAdminKey, "admin_explicit")
	options, err = registrySigningOptions("acme/app")
	require.NoError(t, err)
	require.Empty(t, options, "an admin token uses its separately configured control plane")
}

func TestRegistryEnrollmentRejectsAnUnexpectedScope(t *testing.T) {
	entry := enrollmentFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, registryEnrollmentPath, r.URL.Path)
		require.Equal(t, "Bearer admin_test", r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(registryAccount{OwnerKind: "user", Namespaces: entry.Namespaces, Scope: entry.Scope})
	}))
	defer server.Close()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	identity := authContext{ContextType: "personal", UserID: "user_test"}
	err := enrollRegistry(cmd, cliConfig{ControlplaneURL: server.URL, APIKey: "admin_test"}, identity, configendorsement.PublicScope, false)
	require.ErrorContains(t, err, "expected scope")
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Empty(t, policy.Registries)
	err = enrollRegistry(cmd, cliConfig{}, identity, "", false)
	require.ErrorContains(t, err, "explicit --scope")
}
