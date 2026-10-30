package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var resourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

const (
	keyStatePath         = "/api/sandboxes/owner-key"
	keyUMKPath           = "/api/sandboxes/owner-key/umk"
	maxKeyStateConflicts = 8
)

var (
	errStaleDEK    = errors.New("the synced key no longer matches your key bundle; run `tinfoil login --sync`")
	errNoLocalKeys = errors.New("this machine has no keys for it")
)

// keyState is the authenticated user's key state; controlplane stores only ciphertext and public keys.
type keyState struct {
	Revision    uint64          `json:"revision"`
	DEKID       *string         `json:"dek_id"`
	EncryptedMK *string         `json:"encrypted_mk"`
	Recovery    json.RawMessage `json:"recovery"`
	UMK         []umkEntry      `json:"umk"`
}

type umkEntry struct {
	KeyID     string `json:"key_id"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
}

// keyStateWrite replaces the whole key state from the revision it was read at.
type keyStateWrite struct {
	ExpectedRevision uint64          `json:"expected_revision"`
	DEKID            string          `json:"dek_id"`
	EncryptedMK      string          `json:"encrypted_mk"`
	Recovery         json.RawMessage `json:"recovery"`
}

func fetchKeyState(ctx context.Context, cp *cpClient) (*keyState, error) {
	var state keyState
	if _, err := cp.doContext(ctx, "GET", keyStatePath, nil, nil, nil, &state); err != nil {
		return nil, fmt.Errorf("reading your key state: %w", err)
	}
	if state.DEKID != nil && !validID16(*state.DEKID) || (state.DEKID == nil) != (state.EncryptedMK == nil) {
		return nil, errors.New("controlplane returned an invalid key state")
	}
	return &state, nil
}

func keyStateConflict(err error, code string) bool {
	var conflict *cpError
	return errors.As(err, &conflict) && conflict.Status == 409 && conflict.Message == code
}

// mkSession opens and updates the current user's MK with the DEK synced at login.
type mkSession struct {
	cp      *cpClient
	dek     []byte
	context mkContext
}

func newMKSession(cp *cpClient, scope accountScope) (*mkSession, error) {
	dek, err := syncedKey(cp.login, scope.UserID)
	if err != nil {
		return nil, err
	}
	if dek == nil {
		return nil, fmt.Errorf("%w: synced resources need your sandbox keys on this machine; run `tinfoil login --sync`", errNoLocalKeys)
	}
	return &mkSession{cp, dek.DEK, mkContext{fixedAPIOrigin, scope.UserID, dek.DEKID}}, nil
}

func (s *mkSession) load(ctx context.Context) (*keyState, *mkPayload, error) {
	state, err := fetchKeyState(ctx, s.cp)
	if err != nil {
		return nil, nil, err
	}
	if state.DEKID == nil || *state.DEKID != s.context.DEKID {
		return nil, nil, errStaleDEK
	}
	payload, err := openMK(*state.EncryptedMK, s.dek, s.context)
	return state, payload, err
}

// update applies change to the latest MK and commits it by compare-and-swap. A
// conflict or unknown outcome reloads and reapplies the same change, which finds
// nothing left to do once an earlier attempt landed; ciphertext is never merged.
func (s *mkSession) update(ctx context.Context, change func(*mkPayload) error) (*mkPayload, error) {
	for range maxKeyStateConflicts {
		state, payload, err := s.load(ctx)
		if err != nil {
			return nil, err
		}
		before, err := contractJSON(payload)
		if err != nil {
			return nil, err
		}
		err = change(payload)
		after, encodeErr := contractJSON(payload)
		unchanged := bytes.Equal(before, after)
		clear(before)
		clear(after)
		if err != nil || encodeErr != nil || unchanged {
			return payload, errors.Join(err, encodeErr)
		}
		sealed, err := sealMK(payload, s.dek, s.context)
		if err != nil {
			return nil, err
		}
		_, err = s.cp.doContext(ctx, "PUT", keyStatePath, nil, nil, keyStateWrite{state.Revision, s.context.DEKID, sealed, state.Recovery}, nil)
		var definite *cpError
		if err == nil {
			return payload, nil
		}
		if !keyStateConflict(err, "stale_revision") && errors.As(err, &definite) && definite.Status < 500 {
			return nil, err
		}
	}
	return nil, errors.New("your key bundle kept changing; retry")
}

func findKey(p *mkPayload, match func(*mkResource) bool) *mkResource {
	for i := range p.Resources {
		if match(&p.Resources[i]) {
			return &p.Resources[i]
		}
	}
	return nil
}

// addKey inserts r in key_id byte order; an existing key_id must hold the same key material.
func addKey(p *mkPayload, r mkResource) error {
	i, found := slices.BinarySearchFunc(p.Resources, r.KeyID, func(e mkResource, id string) int { return strings.Compare(e.KeyID, id) })
	if !found {
		if len(p.Resources) >= maxMKResources {
			return errors.New("your key bundle is full; delete unused resources first")
		}
		p.Resources = slices.Insert(p.Resources, i, r)
		return nil
	}
	e := p.Resources[i]
	if e.Kind != r.Kind || e.AttemptID != r.AttemptID || e.OwnerPublicKey != r.OwnerPublicKey || !bytes.Equal(e.OwnerSeed, r.OwnerSeed) ||
		!bytes.Equal(e.StorageKey, r.StorageKey) || !bytes.Equal(e.AgentSeed, r.AgentSeed) {
		return fmt.Errorf("key %s already holds different key material", r.KeyID)
	}
	return nil
}

// newResourceKey generates independent owner, storage and (sandbox) agent keys.
func newResourceKey(kind string) mkResource {
	random := func() b64u {
		key := make(b64u, 32)
		rand.Read(key)
		return key
	}
	r := mkResource{KeyID: randomB64U(16), Kind: kind, AttemptID: randomB64U(16), OwnerSeed: random(), StorageKey: random()}
	r.OwnerPublicKey = ed25519PublicKeyString(r.OwnerSeed)
	if kind == "sandbox" {
		r.AgentSeed = random()
	} else {
		r.MinGeneration = new(uint64)
	}
	return r
}

// resourceKeys are one resource's owner signer and independent secrets for this command.
type resourceKeys struct {
	mode          string
	signer        ssh.Signer
	identity      string
	ownerPrivate  ed25519.PrivateKey
	ownerSeed     []byte
	storageKey    []byte
	agentSeed     []byte
	minGeneration uint64
	closeSigner   func()
	mk            *mkSession
	keyID         string
	umkPath       string
}

func (k *resourceKeys) close() {
	clear(k.ownerPrivate)
	clear(k.ownerSeed)
	clear(k.storageKey)
	clear(k.agentSeed)
	if k.closeSigner != nil {
		k.closeSigner()
	}
}

// resolveResourceKeys finds the saved keys of a resource by its measured owner key
// and, with bind, binds its allocated IDs before first initialization. A missing or
// wrong key fails: an existing resource never gets replacement keys. With bind, a UMK
// resource without a local record returns no secrets, which the caller generates only
// on proof of non-use; without bind, keys that were never bound count as absent.
func resolveResourceKeys(ctx context.Context, cp *cpClient, scope accountScope, row containerView, kind string, binding mkBinding, dir string, bind bool) (*resourceKeys, error) {
	if _, err := measuredOwner(row.OwnerPublicKey); err != nil {
		return nil, err
	}
	keys := &resourceKeys{mode: row.OwnerKeyMode}
	switch row.OwnerKeyMode {
	case "tmk":
		mk, err := newMKSession(cp, scope)
		if err != nil {
			return nil, err
		}
		var saved mkResource
		_, err = mk.update(ctx, func(p *mkPayload) error {
			r := findKey(p, func(r *mkResource) bool { return r.OwnerPublicKey == row.OwnerPublicKey })
			if r == nil || r.Kind != kind {
				return fmt.Errorf("%w: your key bundle has no %s key for %s; it was created by another user or its keys were lost", errNoLocalKeys, kind, row.Name)
			}
			if r.Binding == nil && !bind {
				return fmt.Errorf("%w: %s was never opened", errNoLocalKeys, row.Name)
			}
			if r.Binding == nil {
				r.Binding = &binding
			} else if !reflect.DeepEqual(*r.Binding, binding) {
				return fmt.Errorf("%s no longer matches the account, resource, volume or storage its keys are bound to", row.Name)
			}
			saved = *r
			return nil
		})
		if err != nil {
			return nil, err
		}
		keys.mk, keys.keyID = mk, saved.KeyID
		keys.ownerSeed, keys.storageKey, keys.agentSeed = bytes.Clone(saved.OwnerSeed), bytes.Clone(saved.StorageKey), bytes.Clone(saved.AgentSeed)
		if saved.MinGeneration != nil {
			keys.minGeneration = *saved.MinGeneration
		}
		// The signer signs with this key until close clears it.
		keys.ownerPrivate = ed25519.NewKeyFromSeed(keys.ownerSeed)
		keys.signer, err = ssh.NewSignerFromKey(keys.ownerPrivate)
		return keys, err
	case "umk":
		var err error
		if keys.umkPath, err = umkRecordPath(scope, row.OwnerPublicKey); err != nil {
			return nil, err
		}
		var record umkRecord
		switch err := readStorageJSON(keys.umkPath, &record); {
		case errors.Is(err, os.ErrNotExist) && !bind:
			return nil, fmt.Errorf("%w: %s has no local storage keys", errNoLocalKeys, row.Name)
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			if err := record.use(keys, kind, row.OwnerPublicKey, binding, bind); err != nil {
				return nil, fmt.Errorf("%s: %w", keys.umkPath, err)
			}
		}
		if err := prepareStorageDirectory(dir); err != nil {
			return nil, err
		}
		keys.signer, keys.identity, keys.closeSigner, err = userSigner(row.OwnerPublicKey, dir)
		if err != nil {
			keys.close()
			return nil, err
		}
		return keys, nil
	}
	return nil, fmt.Errorf("%s has no supported owner key custody; recreate it", row.Name)
}

// umkRecord holds a UMK resource's locally generated storage and agent keys; its owner key stays the user's.
type umkRecord struct {
	Version    int        `json:"version"`
	Kind       string     `json:"kind"`
	Owner      string     `json:"owner_public_key"`
	StorageKey b64u       `json:"storage_key"`
	AgentSeed  b64u       `json:"agent_seed"`
	Binding    *mkBinding `json:"binding"`
}

func umkRecordPath(scope accountScope, owner string) (string, error) {
	dir, err := accountDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "umk-"+storageHash([]byte(owner))[:32]+".json"), nil
}

func newUMKRecord(kind, owner string) *umkRecord {
	r := newResourceKey(kind)
	clear(r.OwnerSeed)
	return &umkRecord{Version: 1, Kind: kind, Owner: owner, StorageKey: r.StorageKey, AgentSeed: r.AgentSeed}
}

// saveUMKRecord publishes new keys exclusively; a concurrent creator's record wins and is returned.
func saveUMKRecord(path string, record *umkRecord) (*umkRecord, error) {
	err := writeStorageJSON(path, record, true)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	var saved umkRecord
	if err := readStorageJSON(path, &saved); err != nil {
		return nil, err
	}
	if saved.Owner != record.Owner || saved.Kind != record.Kind {
		return nil, fmt.Errorf("%s holds keys of another resource", path)
	}
	if err == nil {
		fmt.Fprintf(os.Stderr, "Back up %s: it holds this resource's storage keys, which your SSH key cannot recover.\n", path)
	}
	return &saved, nil
}

func (r *umkRecord) use(keys *resourceKeys, kind, owner string, binding mkBinding, bind bool) error {
	if r.Version != 1 || r.Kind != kind || r.Owner != owner || len(r.StorageKey) != 32 || (kind == "sandbox") != (len(r.AgentSeed) == 32) {
		return errors.New("the local storage keys belong to another resource or are damaged; restore the original file")
	}
	if r.Binding != nil && !reflect.DeepEqual(*r.Binding, binding) {
		return errors.New("the resource no longer matches the account, resource, volume or storage its keys are bound to")
	}
	if r.Binding == nil && !bind {
		return fmt.Errorf("%w: it was never opened", errNoLocalKeys)
	}
	if r.Binding == nil {
		r.Binding = &binding
		if err := writeStorageJSON(keys.umkPath, r, false); err != nil {
			return err
		}
	}
	keys.storageKey, keys.agentSeed = bytes.Clone(r.StorageKey), bytes.Clone(r.AgentSeed)
	return nil
}

// generateUMKKeys creates and saves a web-provisioned UMK resource's keys once its storage is proven unused.
func (k *resourceKeys) generateUMKKeys(kind, owner string, binding mkBinding) error {
	record := newUMKRecord(kind, owner)
	record.Binding = &binding
	saved, err := saveUMKRecord(k.umkPath, record)
	clear(record.StorageKey)
	clear(record.AgentSeed)
	if err != nil {
		return err
	}
	return saved.use(k, kind, owner, binding, true)
}

// registerUMK records a UMK public key before provisioning; no MK or passkey is involved.
func registerUMK(ctx context.Context, cp *cpClient, kind, owner string) error {
	state, err := fetchKeyState(ctx, cp)
	if err != nil {
		return err
	}
	for _, entry := range state.UMK {
		if entry.PublicKey == owner {
			if entry.Kind != kind {
				return fmt.Errorf("this owner key is registered for a %s; choose a distinct key for each resource", entry.Kind)
			}
			return nil
		}
	}
	_, err = cp.doContext(ctx, "POST", keyUMKPath, nil, nil, map[string][]umkEntry{"umk": {{KeyID: randomB64U(16), Kind: kind, PublicKey: owner}}}, nil)
	return err
}

// whileSignedIn writes CLI-managed TMK material only while the login that synced it
// is current, so a delayed command cannot recreate what logout removed.
func whileSignedIn(login *clerkGrant, write func() error) error {
	return withCredentialLock(func() error {
		current, err := currentGrant()
		if err != nil {
			return err
		}
		if login == nil || current == nil || current.Grant != login.Grant {
			return errors.New("you signed out while connecting; run `tinfoil login --sync`")
		}
		return write()
	})
}

// exportTMKIdentity writes a synced owner key for native SSH. Only this file name marks
// a CLI-managed export; user keys never use it.
func exportTMKIdentity(login *clerkGrant, dir string, seed []byte) (string, error) {
	path := filepath.Join(dir, tmkOwnerKeyName)
	return path, whileSignedIn(login, func() error {
		if err := prepareStorageDirectory(dir); err != nil {
			return err
		}
		_, err := ensureSSHIdentity(path, seed)
		return err
	})
}

// removeExportedKeys deletes the owner keys exported from synced resources and the
// device keys of synced Monitors, first removing them from ssh-agent, where ssh's
// AddKeysToAgent may have placed them.
func removeExportedKeys() error {
	config, err := configPath()
	if err != nil {
		return err
	}
	resources := filepath.Join(filepath.Dir(config), "resources")
	exported, err := filepath.Glob(filepath.Join(resources, "*", "*", tmkOwnerKeyName))
	if err != nil {
		return err
	}
	profiles, _ := filepath.Glob(filepath.Join(resources, "*", "*", monitorProfileFile))
	for _, path := range profiles {
		var profile monitorProfile
		if readStorageJSON(path, &profile) == nil && profile.Custody == "tmk" {
			exported = append(exported, filepath.Join(filepath.Dir(path), monitorDeviceKeyName))
		}
	}
	var keys agent.ExtendedAgent
	var loaded []*agent.Key
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, dialErr := net.Dial("unix", socket); dialErr == nil {
			defer conn.Close()
			keys = agent.NewClient(conn)
			loaded, _ = keys.List()
		}
	}
	for _, path := range exported {
		if signer, loadErr := loadSigner(path); loadErr == nil {
			public := signer.PublicKey()
			if slices.ContainsFunc(loaded, func(key *agent.Key) bool { return bytes.Equal(key.Marshal(), public.Marshal()) }) {
				err = errors.Join(err, keys.Remove(public))
			}
		}
		if removeErr := os.Remove(path); !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}
	return err
}

// forgetDeletedResource removes a resource's keys after its deletion is confirmed in
// the owning account. A sandbox keeps its disk key while its workspace volume exists.
func forgetDeletedResource(ctx context.Context, cp *cpClient, scope accountScope, row containerView) error {
	var gone *cpError
	if _, err := cp.doContext(ctx, "GET", pathf("/api/containers/%s", row.ID), nil, nil, nil, nil); !errors.As(err, &gone) || gone.Status != 404 {
		return errors.Join(errors.New("deletion is not confirmed yet; its keys are kept"), err)
	}
	if volume := row.Volumes["workspace"]; volume != "" {
		list, err := listVolumes(cp)
		if err != nil || slices.ContainsFunc(list.Volumes, func(v volumeView) bool { return v.ID == volume }) {
			return errors.Join(fmt.Errorf("its workspace volume %s still exists or could not be checked, so its disk key is kept", volume), err)
		}
	}
	switch row.OwnerKeyMode {
	case "tmk":
		mk, err := newMKSession(cp, scope)
		if err != nil {
			return err
		}
		_, err = mk.update(ctx, func(p *mkPayload) error {
			p.Resources = slices.DeleteFunc(p.Resources, func(r mkResource) bool {
				return r.Binding != nil && r.Binding.ContainerID == row.ID && r.Binding.Account == scope.account()
			})
			return nil
		})
		return err
	case "umk":
		state, err := fetchKeyState(ctx, cp)
		if err != nil {
			return err
		}
		for _, entry := range state.UMK {
			if entry.PublicKey == row.OwnerPublicKey {
				_, err := cp.doContext(ctx, "DELETE", pathf(keyUMKPath+"/%s", entry.KeyID), nil, nil, nil, nil)
				return err
			}
		}
	}
	return nil
}

func ensureSSHKey(path string) (string, error) {
	signer, err := ensureSSHIdentity(path, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// A supplied seed must match the saved identity; otherwise concurrent creators
// adopt the winner without overwriting it. Encryption keys are never involved.
func ensureSSHIdentity(path string, seed []byte) (ssh.Signer, error) {
	ownerSeed := seed
	saved, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if seed == nil {
			seed = make([]byte, ed25519.SeedSize)
			rand.Read(seed)
			defer clear(seed)
		}
		private := ed25519.NewKeyFromSeed(seed)
		defer clear(private)
		block, marshalErr := ssh.MarshalPrivateKey(private, "")
		if marshalErr != nil {
			return nil, marshalErr
		}
		encoded := pem.EncodeToMemory(block)
		defer clear(encoded)
		if err := writeStorageFile(path, encoded, true); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		saved, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	defer clear(saved)
	signer, err := ssh.ParsePrivateKey(saved)
	if err != nil {
		return nil, err
	}
	if ownerSeed != nil {
		private := ed25519.NewKeyFromSeed(ownerSeed)
		defer clear(private)
		key, _ := ssh.NewPublicKey(private.Public())
		if !bytes.Equal(signer.PublicKey().Marshal(), key.Marshal()) {
			return nil, errors.New("saved SSH identity does not match the measured owner key")
		}
	}
	return signer, nil
}

func measuredOwner(value string) (ssh.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || !strings.HasPrefix(value, "ed25519:") || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("workload requires a measured Ed25519 owner public key")
	}
	return ssh.NewPublicKey(ed25519.PublicKey(raw))
}

// Names make new directories readable; UUIDs identify existing credentials even
// after a resource is renamed. Keep saved paths stable for installed SSH profiles.
func resourceDir(scope accountScope, id, name string) (string, error) {
	if !looksLikeUUID(id) {
		return "", errors.New("invalid resource UUID")
	}
	accountDir, err := accountDir(scope)
	if err != nil {
		return "", err
	}
	dir, err := existingCredentialDir(accountDir, id)
	if err != nil || dir != "" {
		return dir, err
	}
	name = strings.TrimSpace(name)
	if !resourceNamePattern.MatchString(name) {
		// Readable labels are optional, including on the first connection.
		return filepath.Join(accountDir, id), nil
	}
	return filepath.Join(accountDir, name+"-"+id), nil
}

func accountDir(scope accountScope) (string, error) {
	config, err := configPath()
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(scope)
	root, accountID := filepath.Join(filepath.Dir(config), "resources"), storageHash(data)
	dir, err := existingCredentialDir(root, accountID)
	if err != nil || dir != "" {
		return dir, err
	}
	return filepath.Join(root, accountDirectoryLabel(scope)+"-"+accountID), nil
}

func accountDirectoryLabel(scope accountScope) string {
	name := strings.TrimSpace(scope.UserName)
	if name == "" {
		name = scope.UserID
	}
	account := "user-" + name
	if scope.OrgID != "" {
		name := strings.TrimSpace(scope.OrgName)
		if name == "" {
			name = scope.OrgID
		}
		account = "org-" + name
	}
	// Keep paths portable and bounded even when organization names contain
	// separators or Unicode. The full scope hash retains their exact identity.
	parts := strings.FieldsFunc(strings.ToLower(account), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_')
	})
	label := strings.Join(parts, "-")
	if len(label) > 120 {
		label = label[:120]
	}
	return strings.Trim(label, ".-_")
}

// Resolve both readable directories and the deployed identifier-only layout.
// A changed display name must not move credentials referenced by SSH profiles.
func existingCredentialDir(parent, id string) (string, error) {
	entries, err := os.ReadDir(parent)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var saved string
	for _, entry := range entries {
		if entry.Name() != id && !strings.HasSuffix(entry.Name(), "-"+id) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		if !entry.IsDir() {
			return "", fmt.Errorf("credential path %s must be a directory", path)
		}
		if saved != "" {
			return "", fmt.Errorf("multiple credential directories for %s: %s and %s; restore a single original credential directory", id, saved, path)
		}
		saved = path
	}
	return saved, nil
}

// userSigner finds a UMK owner's own Ed25519 key in a file or ssh-agent. A public
// identity file selects an ssh-agent key without copying its private key.
func userSigner(owner, dir string) (ssh.Signer, string, func(), error) {
	close := func() {}
	public, err := measuredOwner(owner)
	if err != nil {
		return nil, "", close, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", close, err
	}
	paths := []string{attestSSHIdentity, filepath.Join(home, ".ssh", "id_ed25519")}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "~/") {
			path = filepath.Join(home, path[2:])
		}
		path, err = filepath.Abs(path)
		if err != nil {
			continue
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		signer, parseErr := ssh.ParsePrivateKey(raw)
		var encrypted *ssh.PassphraseMissingError
		if errors.As(parseErr, &encrypted) && encrypted.PublicKey != nil && bytes.Equal(encrypted.PublicKey.Marshal(), public.Marshal()) {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				clear(raw)
				continue
			}
			fmt.Fprintf(os.Stderr, "Passphrase for %s: ", path)
			password, passwordErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if passwordErr != nil {
				clear(raw)
				clear(password)
				return nil, "", close, passwordErr
			}
			signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(raw, password)
			clear(password)
		}
		clear(raw)
		if parseErr == nil && bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
			return signer, path, close, nil
		}
	}
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		conn, dialErr := net.Dial("unix", socket)
		if dialErr == nil {
			signers, _ := agent.NewClient(conn).Signers()
			for _, signer := range signers {
				if bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
					path := filepath.Join(dir, "owner.pub")
					if err := writeAtomic(path, ssh.MarshalAuthorizedKey(public)); err != nil {
						conn.Close()
						return nil, "", close, err
					}
					return signer, path, func() { conn.Close() }, nil
				}
			}
			conn.Close()
		}
	}
	return nil, "", close, fmt.Errorf("%w: owner %s requires its Ed25519 key through --identity or ssh-agent", errNoLocalKeys, ssh.FingerprintSHA256(public))
}
