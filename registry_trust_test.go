package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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
	return registryEnrollment{ControlplaneURL: defaultControlplaneURL, AccountID: "org_acme", Label: "Acme", Namespaces: []string{"/acme"}, RegistryID: configendorsement.RegistryIDPrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"}
}

func TestRegistryEnrollmentRequiresExplicitAcceptanceAndReplacement(t *testing.T) {
	entry := enrollmentFixture(t)
	var output bytes.Buffer
	require.NoError(t, acceptRegistry(strings.NewReader("no\n"), &output, entry, false))
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Empty(t, policy.Registries)
	require.NoError(t, acceptRegistry(strings.NewReader("yes\n"), &output, entry, false))
	require.Contains(t, output.String(), "Registry ID: "+entry.RegistryID)
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []registryEnrollment{entry}, policy.Registries)
	changed := entry
	changed.RegistryID = configendorsement.RegistryIDPrefix + "ffffffffffffffffffffffffffffffff"
	require.NoError(t, acceptRegistry(strings.NewReader("\n"), &output, changed, false))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, entry.RegistryID, policy.Registries[0].RegistryID)
	require.NoError(t, acceptRegistry(strings.NewReader("yes\n"), &output, changed, false))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, changed.RegistryID, policy.Registries[0].RegistryID)
	require.Len(t, policy.Registries, 1)
}

func TestRegistryCommandsKeepPersonalAndOrganizationApprovalsSeparate(t *testing.T) {
	entry := enrollmentFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/context":
			json.NewEncoder(w).Encode(map[string]any{"context_type": "organization", "user_id": "user_owner", "organization": map[string]string{"id": entry.AccountID, "name": entry.Label}})
		case registryEnrollmentPath:
			json.NewEncoder(w).Encode(registryAccount{OwnerKind: "organization", Namespaces: entry.Namespaces, RegistryID: entry.RegistryID})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv(envCPURL, server.URL)
	t.Setenv(envAdminKey, "admin_fixture")
	personal := entry
	personal.AccountID, personal.Namespaces, personal.RegistryID = "user_owner", []string{"/user-personal"}, configendorsement.RegistryIDPrefix+strings.Repeat("f", 32)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, personal, true))
	require.NoError(t, executeLifecycleCLI(newCommandFixture(), t, "trust", "add", "--registry-id", entry.RegistryID))
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Len(t, policy.Registries, 2)
	output, err := captureTestStdout(func() error { return executeLifecycleCLI(newCommandFixture(), t, "trust") })
	require.NoError(t, err)
	require.Contains(t, string(output), "Private registry: Acme")
	require.NotContains(t, string(output), entry.RegistryID)
	output, err = captureTestStdout(func() error { return executeLifecycleCLI(newCommandFixture(), t, "trust", "--json") })
	require.NoError(t, err)
	require.Contains(t, string(output), `"registry_id":"`+entry.RegistryID+`"`)
	require.NoError(t, executeLifecycleCLI(newCommandFixture(), t, "trust", "remove", entry.Label))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []registryEnrollment{personal}, policy.Registries)
}

func TestRegistryRemovalRejectsAmbiguousNames(t *testing.T) {
	entry := enrollmentFixture(t)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, entry, true))
	other := entry
	other.AccountID, other.Namespaces, other.RegistryID = "org_other", []string{"/other"}, configendorsement.RegistryIDPrefix+strings.Repeat("e", 32)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, other, true))
	require.ErrorContains(t, executeLifecycleCLI(newCommandFixture(), t, "trust", "remove", entry.Label), "multiple private registries")
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Len(t, policy.Registries, 2)
	other.Label = entry.AccountID
	require.NoError(t, policy.AcceptRegistry(other))
	require.NoError(t, executeLifecycleCLI(newCommandFixture(), t, "trust", "remove", entry.AccountID))
	policy, err = loadConnectionPolicy()
	require.NoError(t, err)
	require.Equal(t, []registryEnrollment{other}, policy.Registries)
}

func TestPublicRegistryPolicySurvivesSSHProxyCommand(t *testing.T) {
	command, err := proxyCommand(&rootOptions{publicRegistry: true}, &tunnelOptions{}, &tunnelTarget{host: "app.example.com", repo: "acme/app"}, defaultSSHPort)
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
	err := enrollRegistry(cmd, cliConfig{ControlplaneURL: server.URL, APIKey: "admin_fixture"}, authContext{}, entry.RegistryID, false)
	require.ErrorContains(t, err, "refusing a controlplane redirect")
	require.Equal(t, 1, requests)
}

func TestRegistryEnrollmentSelectsOnlyItsNamespacesAndControlPlane(t *testing.T) {
	rootOpts := newCommandFixture().rootOpts
	entry := enrollmentFixture(t)
	require.NoError(t, acceptRegistry(strings.NewReader(""), &bytes.Buffer{}, entry, true))
	options, err := registryIDs(rootOpts, "acme/app@v1")
	require.NoError(t, err)
	v, err := verify.NewVerifier(verify.WithConfigRegistryIDs(options...))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	doc, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(doc, nonce, "acme/app")
	require.ErrorContains(t, err, "configured trust requires")
	options, err = registryIDs(rootOpts, "other/app")
	require.NoError(t, err)
	require.Empty(t, options)
	t.Setenv(envCPURL, "https://another-controlplane.example")
	options, err = registryIDs(rootOpts, "acme/app")
	require.NoError(t, err)
	require.Empty(t, options)
	t.Setenv(envCPURL, defaultControlplaneURL)
	rootOpts.publicRegistry = true
	options, err = registryIDs(rootOpts, "acme/app")
	require.NoError(t, err)
	require.Empty(t, options)
	require.NoError(t, os.WriteFile(os.Getenv(envKnownConfigs), []byte("invalid"), 0600))
	_, err = registryIDs(rootOpts, "acme/app")
	require.ErrorContains(t, err, "malformed")
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
	options, err := registryIDs(newCommandFixture().rootOpts, "acme/app")
	require.NoError(t, err)
	require.Len(t, options, 1, "a URL override cannot bypass the Clerk account's enrolled registry")
	t.Setenv(envAdminKey, "admin_explicit")
	options, err = registryIDs(newCommandFixture().rootOpts, "acme/app")
	require.NoError(t, err)
	require.Empty(t, options, "an admin token uses its separately configured control plane")
}

func TestRegistryEnrollmentRejectsAnUnexpectedRegistryID(t *testing.T) {
	entry := enrollmentFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, registryEnrollmentPath, r.URL.Path)
		assert.Equal(t, "Bearer admin_test", r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(registryAccount{OwnerKind: "user", Namespaces: entry.Namespaces, RegistryID: entry.RegistryID})
	}))
	defer server.Close()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	identity := authContext{ContextType: "personal", UserID: "user_test"}
	err := enrollRegistry(cmd, cliConfig{ControlplaneURL: server.URL, APIKey: "admin_test"}, identity, configendorsement.PublicRegistryID, false)
	require.ErrorContains(t, err, "expected registry ID")
	policy, err := loadConnectionPolicy()
	require.NoError(t, err)
	require.Empty(t, policy.Registries)
	err = enrollRegistry(cmd, cliConfig{}, identity, "", false)
	require.ErrorContains(t, err, "explicit --registry-id")
}

func TestRegistryEnrollmentRejectsUnsafeURLsBeforeSendingCredentials(t *testing.T) {
	entry := enrollmentFixture(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		json.NewEncoder(w).Encode(registryAccount{OwnerKind: "user", Namespaces: entry.Namespaces, RegistryID: entry.RegistryID})
	}))
	defer server.Close()
	for _, address := range []string{
		strings.Replace(server.URL, "://", "://user:password@", 1),
		server.URL + "?token=fixture",
		server.URL + "?",
		server.URL + "#fragment",
	} {
		cmd := &cobra.Command{}
		cmd.SetErr(&bytes.Buffer{})
		err := enrollRegistry(cmd, cliConfig{ControlplaneURL: address, APIKey: "admin_fixture"}, authContext{ContextType: "personal", UserID: "user_owner"}, entry.RegistryID, false)
		require.ErrorContains(t, err, "must not contain")
	}
	require.Zero(t, requests.Load())
}
