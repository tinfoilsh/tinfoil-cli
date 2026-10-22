package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testOwnerCredential(t *testing.T) *ownerCredential {
	t.Helper()
	c := &ownerCredential{Version: 2, Key: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	rand.Read(c.Key)
	rand.Read(c.SigningSeed)
	return c
}

func ensureOwnerSSHKey(path string, seed []byte) error {
	_, err := ensureSSHIdentity(path, seed)
	return err
}

func TestOwnerCredentialCompatibilityAndCustody(t *testing.T) {
	dir, owner := t.TempDir(), testOwnerCredential(t)
	old := attestSSHIdentity
	attestSSHIdentity = filepath.Join(dir, "identity")
	t.Cleanup(func() { attestSSHIdentity = old })
	require.NoError(t, ensureOwnerSSHKey(attestSSHIdentity, owner.SigningSeed))
	for _, version := range []int{2, 3} {
		c := *owner
		c.Version = version
		if version == 3 {
			c.Owner, c.SigningSeed = owner.publicKey(), nil
		}
		file := fmt.Sprint(version)
		path := filepath.Join(dir, file)
		require.NoError(t, saveOwnerCredential(path, &c))
		require.NoError(t, saveOwnerCredential(path, &c))
		require.ErrorContains(t, saveOwnerCredential(path, testOwnerCredential(t)), "different credential")
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		loaded, err := resourceCredential(dir, file, owner.publicKey(), true)
		require.NoError(t, err)
		signer, _, close, err := ownerSigner(loaded, dir)
		require.NoError(t, err)
		close()
		expected, err := measuredOwner(owner.publicKey())
		require.NoError(t, err)
		require.Equal(t, expected.Marshal(), signer.PublicKey().Marshal())
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.NoError(t, os.Remove(path))
		_, err = resourceCredential(dir, file, owner.publicKey(), true)
		require.ErrorContains(t, err, "restore encryption credentials")
		require.NoFileExists(t, path)
	}
	valid, err := json.Marshal(owner)
	require.NoError(t, err)
	for _, raw := range []string{"short", strings.Repeat("x", 4097), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), string(valid) + " {}", strings.Replace(string(valid), `"version":2`, `"version":1`, 1), strings.Replace(string(valid), `"version":2`, `"version":2,"unknown":true`, 1)} {
		path := filepath.Join(dir, "invalid")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, err := readOwnerCredential(path)
		require.Error(t, err)
	}
}

func TestConcurrentCredentialCreationPreservesWinner(t *testing.T) {
	owner := testOwnerCredential(t)
	for _, seed := range [][]byte{nil, owner.SigningSeed} {
		dir := t.TempDir()
		path := filepath.Join(dir, "identity")
		results := make(chan string, 16)
		ready, start, encrypt := make(chan struct{}, 16), make(chan struct{}), make(chan struct{})
		for range 16 {
			go func() {
				ready <- struct{}{}
				<-start
				signer, sshErr := ensureSSHIdentity(path, seed)
				ready <- struct{}{}
				<-encrypt
				c, err := resourceCredential(dir, "disk.key", owner.publicKey(), false)
				if c != nil {
					defer c.clear()
				}
				if err := errors.Join(sshErr, err); err != nil {
					t.Error(err)
					results <- ""
					return
				}
				results <- authorizedLine(signer) + base64.StdEncoding.EncodeToString(c.Key)
			}()
		}
		for _, gate := range []chan struct{}{start, encrypt} {
			for range 16 {
				<-ready
			}
			close(gate)
		}
		first := <-results
		for range 15 {
			if first != <-results {
				t.Error("concurrent creators returned different keys")
			}
		}
		require.NotEmpty(t, first)
		require.ErrorContains(t, ensureOwnerSSHKey(path, testOwnerCredential(t).SigningSeed), "does not match")
		_, err := resourceCredential(dir, "disk.key", testOwnerCredential(t).publicKey(), false)
		require.ErrorContains(t, err, "measured owner changed")
	}
}

func TestEncryptedOwnerIdentityFallsBackToAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	previousStdin, previousIdentity := os.Stdin, attestSSHIdentity
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin, attestSSHIdentity = previousStdin, previousIdentity; stdin.Close() })
	credential := testOwnerCredential(t)
	private := ed25519.NewKeyFromSeed(credential.SigningSeed)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("test password"))
	require.NoError(t, err)
	attestSSHIdentity = filepath.Join(home, "encrypted-owner")
	require.NoError(t, os.WriteFile(attestSSHIdentity, pem.EncodeToMemory(block), 0600))
	socket := filepath.Join(home, "agent.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: private}))
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- agent.ServeAgent(keyring, conn)
	}()
	signer, path, closeSigner, err := ownerSigner(&ownerCredential{Version: 3, Owner: credential.publicKey()}, home)
	require.NoError(t, err)
	defer closeSigner()
	require.Equal(t, filepath.Join(home, "owner.pub"), path)
	message := []byte("prove the agent can sign without an interactive prompt")
	signature, err := signer.Sign(nil, message)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(message, signature))
	closeSigner()
	require.ErrorIs(t, <-done, io.EOF)
}

func TestCredentialsUseOnlyResourcePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: monitorRepo}
	data, err := json.Marshal(scope)
	require.NoError(t, err)
	require.NoError(t, writeStorageJSON(filepath.Join(home, "sandboxes", row.Name, "monitor.json"), map[string]any{"scope": scope, "monitor": "personal"}, false))
	require.NoError(t, writeStorageJSON(filepath.Join(home, "monitors", storageHash(data), row.Name, monitorProfileFile), monitorProfile{ContainerID: row.ID, Generation: 7}, false))
	got, err := monitorRecord(scope, &workloadTarget{containerView: row})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "resources", "user-owner-"+storageHash(data), "work-"+row.ID), got)
}

func TestAccountDirectoriesUseAuthenticatedDisplayNames(t *testing.T) {
	for _, test := range []struct {
		name, response, prefix, orgID string
	}{
		{"organization", `{"context_type":"organization","organization":{"id":"org_1","name":"Acme Labs"},"user_id":"user_1"}`, "org-acme-labs-", "org_1"},
		{"personal", `{"context_type":"personal","organization":null,"user_id":"user_1","user_name":"Ada Lovelace"}`, "user-ada-lovelace-", ""},
		{"older API", `{"context_type":"personal","organization":null,"user_id":"user_1"}`, "user-user_1-", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/auth/context" {
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				io.WriteString(w, test.response)
			}))
			defer server.Close()
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			t.Setenv(envCPURL, server.URL)
			t.Setenv(envAdminKey, "admin_test")
			scope, _, err := currentScope()
			require.NoError(t, err)
			row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo}
			dir, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			data, err := json.Marshal(accountScope{ControlplaneURL: server.URL, OrgID: test.orgID, UserID: "user_1"})
			require.NoError(t, err)
			require.Equal(t, test.prefix+storageHash(data), filepath.Base(filepath.Dir(dir)), "display names must not change the deployed scope hash")
			owner := testOwnerCredential(t)
			require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), owner, true))
			scope.OrgName, scope.UserName, row.Name = "", "", ""
			got, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, dir, got, "lookup must not need either display name")
		})
	}
}

func TestAccountDirectoryLabelsAreSafeAndBounded(t *testing.T) {
	for _, name := range []string{"", "../../Acme / Labs\\team", strings.Repeat("company", 100), "会社"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example:8443", OrgID: "org_1", UserID: "owner", OrgName: name}
			dir, err := resourceDir(scope, "11111111-1111-4111-8111-111111111111", "work")
			require.NoError(t, err)
			accountDir := filepath.Dir(dir)
			require.Equal(t, filepath.Join(home, "resources"), filepath.Dir(accountDir))
			require.LessOrEqual(t, len(filepath.Base(accountDir)), 255)
			require.NotContains(t, filepath.Base(accountDir), "\\")
			require.True(t, strings.HasPrefix(filepath.Base(accountDir), "org-"))
			if name == "" {
				require.True(t, strings.HasPrefix(filepath.Base(accountDir), "org-org_1-"))
			}
			require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), testOwnerCredential(t), true))
		})
	}
}

func TestResourceCredentialsSurviveRenameAndSeparateRecreatedResources(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", OrgID: "org", UserID: "owner", OrgName: "Acme"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "my-work"}
	dir, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, row.Name+"-"+row.ID, filepath.Base(dir))
	require.True(t, strings.HasPrefix(filepath.Base(filepath.Dir(dir)), "org-acme-"))
	owner := testOwnerCredential(t)
	require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), owner, true))

	row.Name, scope.OrgName = "renamed-work", "Renamed Acme"
	renamed, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, renamed, "installed SSH identity paths must stay valid")
	credential, err := resourceCredential(renamed, sandboxDiskKeyName, owner.publicKey(), true)
	require.NoError(t, err)
	defer credential.clear()
	require.Equal(t, owner.Key, credential.Key)
	row.Name, scope.OrgName = "", ""
	unnamed, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, unnamed, "resource and account names are optional for lookup")
	row.Name = "renamed-work"
	scope.OrgName = "Acme"

	for _, otherScope := range []accountScope{
		{ControlplaneURL: "https://other.example", OrgID: scope.OrgID, UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL + "/other", OrgID: scope.OrgID, UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL, OrgID: "other", UserID: scope.UserID, OrgName: scope.OrgName},
		{ControlplaneURL: scope.ControlplaneURL, OrgID: scope.OrgID, UserID: "other", OrgName: scope.OrgName},
	} {
		other, err := resourceDir(otherScope, row.ID, row.Name)
		require.NoError(t, err)
		require.NotEqual(t, filepath.Dir(dir), filepath.Dir(other))
		require.NoDirExists(t, other)
	}

	row.Name, row.ID = "my-work", "22222222-2222-4222-8222-222222222222"
	recreated, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(filepath.Dir(dir), row.Name+"-"+row.ID), recreated)
	require.NoDirExists(t, recreated, "reusing a name must not reuse credentials")
}

func TestResourceCredentialsWithoutUsableName(t *testing.T) {
	for _, test := range []struct {
		name, label     string
		existingAccount bool
	}{
		{"new account", "../work", false},
		{"existing account", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
			hash := storageHash([]byte(`{"controlplane_url":"https://cp.example","user_id":"owner"}`))
			accountDir := filepath.Join(home, "resources", "user-owner-"+hash)
			if test.existingAccount {
				accountDir = filepath.Join(home, "resources", "saved-label-"+hash)
				require.NoError(t, os.MkdirAll(accountDir, 0700))
			}
			row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: test.label}
			dir, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, filepath.Join(accountDir, row.ID), dir)
			owner := testOwnerCredential(t)
			require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), owner, true))
			row.Name = "readable-name"
			got, err := resourceDir(scope, row.ID, row.Name)
			require.NoError(t, err)
			require.Equal(t, dir, got, "a later usable name must preserve the existing credential path")
			credential, err := resourceCredential(got, sandboxDiskKeyName, owner.publicKey(), true)
			require.NoError(t, err)
			defer credential.clear()
			require.Equal(t, owner.Key, credential.Key)
		})
	}
}

func TestExistingResourcePathsRemainUsable(t *testing.T) {
	home := t.TempDir()
	t.Setenv(envConfigPath, filepath.Join(home, "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", OrgID: "org", UserID: "owner", OrgName: "Acme"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work"}
	named, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	// Resources saved without display labels keep their original hash and path.
	hash := storageHash([]byte(`{"controlplane_url":"https://cp.example","org_id":"org","user_id":"owner"}`))
	dir := filepath.Join(home, "resources", hash, row.ID)
	owner := testOwnerCredential(t)
	require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), owner, true))
	before, err := os.ReadFile(filepath.Join(dir, sandboxDiskKeyName))
	require.NoError(t, err)
	got, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	require.Equal(t, dir, got)
	credential, err := resourceCredential(got, sandboxDiskKeyName, owner.publicKey(), true)
	require.NoError(t, err)
	defer credential.clear()
	require.Equal(t, owner.Key, credential.Key)
	after, err := os.ReadFile(filepath.Join(dir, sandboxDiskKeyName))
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.NoDirExists(t, filepath.Dir(named))
}

func TestResourceCredentialsRejectAmbiguousDirectories(t *testing.T) {
	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
	scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
	row := containerView{ID: "11111111-1111-4111-8111-111111111111", Name: "work", Repo: defaultSandboxRepo}
	dir, err := resourceDir(scope, row.ID, row.Name)
	require.NoError(t, err)
	owner := testOwnerCredential(t)
	require.NoError(t, writeStorageJSON(filepath.Join(dir, sandboxDiskKeyName), owner, true))
	for _, name := range []string{row.ID, "old-name-" + row.ID} {
		other := filepath.Join(filepath.Dir(dir), name)
		require.NoError(t, os.Mkdir(other, 0700))
		_, err := resourceDir(scope, row.ID, row.Name)
		require.ErrorContains(t, err, "multiple credential directories")
		require.NoError(t, os.Remove(other))
	}
	data, err := json.Marshal(scope)
	require.NoError(t, err)
	accountDir := filepath.Dir(dir)
	for _, name := range []string{storageHash(data), "other-label-" + storageHash(data)} {
		other := filepath.Join(filepath.Dir(accountDir), name)
		require.NoError(t, os.Mkdir(other, 0700))
		_, err := resourceDir(scope, row.ID, row.Name)
		require.ErrorContains(t, err, "multiple credential directories")
		require.NoError(t, os.Remove(other))
	}
	credential, err := readOwnerCredential(filepath.Join(dir, sandboxDiskKeyName))
	require.NoError(t, err)
	defer credential.clear()
	require.Equal(t, owner.Key, credential.Key)
}

func TestWorkspaceCredentialsFollowOnlyTheirAccountAndVolume(t *testing.T) {
	for _, layout := range []string{"UUID", "named"} {
		for _, mode := range []string{"reuse", "account", "volume", "owner", "missing", "conflict", "known without key"} {
			t.Run(layout+"/"+mode, func(t *testing.T) {
				t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
				scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "owner"}
				c := testOwnerCredential(t)
				row := sandboxResource{ID: "11111111-1111-4111-8111-111111111111", Owner: c.publicKey(), Volumes: map[string]string{"workspace": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
				save := func(row sandboxResource, key *ownerCredential) string {
					dir, err := resourceDir(scope, row.ID, "old-work")
					require.NoError(t, err)
					if layout == "UUID" {
						data, err := json.Marshal(scope)
						require.NoError(t, err)
						dir = filepath.Join(filepath.Dir(filepath.Dir(dir)), storageHash(data), row.ID)
					}
					require.NoError(t, writeStorageJSON(filepath.Join(dir, "resource.json"), row, false))
					require.NoError(t, saveOwnerCredential(filepath.Join(dir, sandboxDiskKeyName), key))
					return dir
				}
				oldDir := save(row, c)
				row.ID = "22222222-2222-4222-8222-222222222222"
				switch mode {
				case "account":
					scope.UserID = "other"
				case "volume":
					row.Volumes["workspace"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				case "owner":
					row.Owner = testOwnerCredential(t).publicKey()
				case "missing":
					require.NoError(t, os.Remove(filepath.Join(oldDir, sandboxDiskKeyName)))
				case "conflict":
					other := row
					other.ID = "33333333-3333-4333-8333-333333333333"
					key := *c
					key.Key = make([]byte, 32)
					save(other, &key)
				}
				dir, err := resourceDir(scope, row.ID, "new-work")
				require.NoError(t, err)
				got, err := sandboxWorkspaceCredential(dir, row, mode == "known without key")
				switch mode {
				case "reuse", "account", "volume":
					require.NoError(t, err)
					require.Equal(t, mode == "reuse", string(c.Key) == string(got.Key))
					require.NoFileExists(t, filepath.Join(dir, sandboxAgentKeyName))
					again, err := sandboxWorkspaceCredential(dir, row, true)
					require.NoError(t, err)
					require.Equal(t, got.Key, again.Key)
				default:
					require.Error(t, err)
					require.NoFileExists(t, filepath.Join(dir, sandboxDiskKeyName))
				}
			})
		}
	}
}
