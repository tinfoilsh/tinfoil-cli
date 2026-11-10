package trust

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func enrollmentFixture() Enrollment {
	return Enrollment{ControlplaneURL: "https://api.example.com", AccountID: "org_acme", Namespaces: []string{"/acme"}, RegistryID: configendorsement.RegistryIDPrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"}
}

func TestRegistryEnrollmentRejectsMalformedAndConflictingPolicies(t *testing.T) {
	entry := enrollmentFixture()
	for _, registryID := range []string{"", "not a registry ID", entry.RegistryID + "/", entry.RegistryID + "\n", strings.Replace(entry.RegistryID, "9c4a", "9C4A", 1), strings.Replace(entry.RegistryID, "9c4a", "9c-4a", 1)} {
		invalid := entry
		invalid.RegistryID = registryID
		require.Error(t, validateRegistryEnrollments([]Enrollment{invalid}))
	}
	other := entry
	other.AccountID = "org_other"
	require.ErrorContains(t, validateRegistryEnrollments([]Enrollment{entry, other}), "conflicting")
	other.ControlplaneURL = "https://another-controlplane.example"
	require.NoError(t, validateRegistryEnrollments([]Enrollment{entry, other}))
}

func TestRegistrySelectionAndRemovalRemainOriginScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	policy, err := Load(path)
	require.NoError(t, err)
	entry := enrollmentFixture()
	require.NoError(t, policy.AcceptRegistry(entry))
	other := entry
	other.ControlplaneURL = "https://another-controlplane.example"
	other.RegistryID = configendorsement.RegistryIDPrefix + strings.Repeat("f", 32)
	require.NoError(t, policy.AcceptRegistry(other))
	policy, err = Load(path)
	require.NoError(t, err)
	for _, tc := range []struct {
		source string
		origin string
		public bool
		want   []string
	}{
		{"acme/app@v1", entry.ControlplaneURL, false, []string{entry.RegistryID}},
		{"acme/app@v1", other.ControlplaneURL, false, []string{other.RegistryID}},
		{"other/app", entry.ControlplaneURL, false, nil},
		{"acme/app", "https://unrelated.example", false, nil},
		{"acme/app", entry.ControlplaneURL, true, nil},
	} {
		ids, err := policy.RegistryIDs(tc.source, tc.origin, tc.public)
		require.NoError(t, err)
		require.Equal(t, tc.want, ids)
	}
	require.False(t, policy.Matches("acme/app@v1"), "registry enrollment does not grant project trust")
	require.NoError(t, policy.RemoveRegistry(entry.ControlplaneURL, entry.Namespaces[0]))
	policy, err = Load(path)
	require.NoError(t, err)
	require.Equal(t, []Enrollment{other}, policy.Registries)
}

func TestRegistryValidationPreventsInvalidPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	policy, err := Load(path)
	require.NoError(t, err)
	entry := enrollmentFixture()
	require.NoError(t, policy.AcceptRegistry(entry))
	for _, change := range []func(*Enrollment){
		func(e *Enrollment) { e.ControlplaneURL = "http://api.example.com" },
		func(e *Enrollment) { e.ControlplaneURL += "/" },
		func(e *Enrollment) { e.ControlplaneURL += "?token=secret" },
		func(e *Enrollment) { e.Namespaces = []string{"acme"} },
		func(e *Enrollment) { e.Namespaces = []string{"/acme/project"} },
		func(e *Enrollment) { e.AccountID = "" },
		func(e *Enrollment) { e.RegistryID = "invalid" },
	} {
		invalid := entry
		change(&invalid)
		require.Error(t, policy.AcceptRegistry(invalid))
		policy, err = Load(path)
		require.NoError(t, err)
		require.Equal(t, []Enrollment{entry}, policy.Registries)
	}
}
