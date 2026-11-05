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

	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var resourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

const (
	keyStatePath         = controlplane.KeyStatePath
	maxKeyStateConflicts = 8
)

var errStaleDEK = errors.New("the synced key no longer matches your key bundle; run `tinfoil login --sync`")

type noLocalKeys string

func (e noLocalKeys) Error() string { return string(e) }

type keyState = controlplane.KeyState

type keyStateWrite = controlplane.KeyStateWrite

func fetchKeyState(ctx context.Context, cp *cpClient) (*keyState, error) {
	var state keyState
	if _, err := cp.doContext(ctx, "GET", keyStatePath, nil, nil, nil, &state); err != nil {
		return nil, fmt.Errorf("reading your key state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func keyStateConflict(err error, code string) bool {
	var conflict *cpError
	return errors.As(err, &conflict) && conflict.Status == 409 && conflict.Message == code
}

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
		reason, next := "this machine doesn't have your synced keys", "run `tinfoil login --sync`"
		if cp.login == nil {
			reason = "synced keys need a browser login, not an admin API key"
			if source := credentialEnvSource(); source != "" {
				next = "unset " + source + ", then " + next
			}
		}
		return nil, noLocalKeys(reason + "; " + next)
	}
	return &mkSession{cp, dek.DEK, mkContext{APIOrigin: fixedAPIOrigin, UserID: scope.UserID, DEKID: dek.DEKID}}, nil
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
		_, err = s.cp.doContext(ctx, "PUT", keyStatePath, nil, nil, keyStateWrite{ExpectedRevision: state.Revision, DEKID: s.context.DEKID, EncryptedMK: sealed, Recovery: state.Recovery}, nil)
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
		!bytes.Equal(e.StorageKey, r.StorageKey) || !bytes.Equal(e.MonitorIdentitySeed, r.MonitorIdentitySeed) {
		return fmt.Errorf("key %s already holds different key material", r.KeyID)
	}
	return nil
}

func newResourceKey(kind string) mkResource {
	random := func() b64u {
		key := make(b64u, 32)
		rand.Read(key)
		return key
	}
	r := mkResource{KeyID: randomB64U(16), Kind: kind, AttemptID: randomB64U(16), OwnerSeed: random(), StorageKey: random()}
	r.OwnerPublicKey = ed25519PublicKeyString(r.OwnerSeed)
	if kind == "sandbox" {
		r.MonitorIdentitySeed = random()
	} else {
		r.MinGeneration = new(uint64)
	}
	return r
}

type resourceKeys struct {
	mode                string
	signer              ssh.Signer
	identity            string
	ownerPrivate        ed25519.PrivateKey
	ownerSeed           []byte
	storageKey          []byte
	monitorIdentitySeed []byte
	minGeneration       uint64
	closeSigner         func()
	mk                  *mkSession
	keyID               string
	umkPath             string
}

func (k *resourceKeys) close() {
	clear(k.ownerPrivate)
	clear(k.ownerSeed)
	clear(k.storageKey)
	clear(k.monitorIdentitySeed)
	if k.closeSigner != nil {
		k.closeSigner()
	}
}

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
				return noLocalKeys(fmt.Sprintf("your synced keys have no key for %s %s; it was created by another user or its keys were lost", kind, row.Name))
			}
			if r.Binding == nil && !bind {
				return noLocalKeys(row.Name + " was never opened")
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
		keys.ownerSeed, keys.storageKey, keys.monitorIdentitySeed = bytes.Clone(saved.OwnerSeed), bytes.Clone(saved.StorageKey), bytes.Clone(saved.MonitorIdentitySeed)
		if saved.MinGeneration != nil {
			keys.minGeneration = *saved.MinGeneration
		}
		keys.ownerPrivate = ed25519.NewKeyFromSeed(keys.ownerSeed)
		keys.signer, err = ssh.NewSignerFromKey(keys.ownerPrivate)
		return keys, err
	case "umk":
		var err error
		if keys.umkPath, err = umkRecordPath(scope, row.ID); err != nil {
			return nil, err
		}
		var record umkRecord
		switch err := readStorageJSON(keys.umkPath, &record); {
		case errors.Is(err, os.ErrNotExist) && !bind:
			return nil, noLocalKeys(fmt.Sprintf("%s %s has no storage keys on this machine (expected %s)", kind, row.Name, keys.umkPath))
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
		keys.signer, keys.identity, keys.closeSigner, err = userSigner(kind+" "+row.Name, row.OwnerPublicKey, dir)
		if err != nil {
			keys.close()
			return nil, err
		}
		return keys, nil
	}
	return nil, fmt.Errorf("%s has no supported owner key custody; recreate it", row.Name)
}

type umkRecord struct {
	Version             int        `json:"version"`
	Kind                string     `json:"kind"`
	Owner               string     `json:"owner_public_key"`
	StorageKey          b64u       `json:"storage_key"`
	MonitorIdentitySeed b64u       `json:"monitor_identity_seed"`
	Binding             *mkBinding `json:"binding"`
}

func umkRecordPath(scope accountScope, containerID string) (string, error) {
	dir, err := accountDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "umk-"+storageHash([]byte(containerID))[:32]+".json"), nil
}

func newUMKRecord(kind, owner string) *umkRecord {
	r := newResourceKey(kind)
	clear(r.OwnerSeed)
	return &umkRecord{Version: 1, Kind: kind, Owner: owner, StorageKey: r.StorageKey, MonitorIdentitySeed: r.MonitorIdentitySeed}
}

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
	if r.Version != 1 || r.Kind != kind || r.Owner != owner || len(r.StorageKey) != 32 || (kind == "sandbox") != (len(r.MonitorIdentitySeed) == 32) {
		return errors.New("the local storage keys belong to another resource or are damaged; restore the original file")
	}
	if r.Binding != nil && !reflect.DeepEqual(*r.Binding, binding) {
		return errors.New("the resource no longer matches the account, resource, volume or storage its keys are bound to")
	}
	if r.Binding == nil && !bind {
		return noLocalKeys("it was never opened")
	}
	if r.Binding == nil {
		r.Binding = &binding
		if err := writeStorageJSON(keys.umkPath, r, false); err != nil {
			return err
		}
	}
	keys.storageKey, keys.monitorIdentitySeed = bytes.Clone(r.StorageKey), bytes.Clone(r.MonitorIdentitySeed)
	return nil
}

func (k *resourceKeys) generateUMKKeys(kind, owner string, binding mkBinding) error {
	record := newUMKRecord(kind, owner)
	record.Binding = &binding
	saved, err := saveUMKRecord(k.umkPath, record)
	clear(record.StorageKey)
	clear(record.MonitorIdentitySeed)
	if err != nil {
		return err
	}
	return saved.use(k, kind, owner, binding, true)
}

func whileSignedIn(login *clerkGrant, write func() error) error {
	service, err := authService()
	if err != nil {
		return err
	}
	return service.WhileSignedIn(login, write)
}

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

// A public identity file selects an ssh-agent key without copying its private key.
func userSigner(name, owner, dir string) (ssh.Signer, string, func(), error) {
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
	var skipped []string
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
			skipped = append(skipped, readErr.Error())
			continue
		}
		signer, parseErr := ssh.ParsePrivateKey(raw)
		var encrypted *ssh.PassphraseMissingError
		if errors.As(parseErr, &encrypted) && encrypted.PublicKey != nil && bytes.Equal(encrypted.PublicKey.Marshal(), public.Marshal()) {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				clear(raw)
				skipped = append(skipped, path+" needs a passphrase, and there is no terminal to ask for it")
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
			if parseErr != nil {
				clear(raw)
				skipped = append(skipped, "the passphrase for "+path+" was rejected")
				continue
			}
		}
		clear(raw)
		if parseErr == nil && bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
			return signer, path, close, nil
		}
		if parseErr == nil || encrypted != nil {
			skipped = append(skipped, path+" holds a different key")
		} else {
			skipped = append(skipped, path+" is not a private key")
		}
	}
	agentState := "no ssh-agent is running"
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		agentState = "ssh-agent is unreachable"
		conn, dialErr := net.Dial("unix", socket)
		if dialErr == nil {
			signers, signersErr := agent.NewClient(conn).Signers()
			if signersErr == nil {
				agentState = "ssh-agent doesn't hold it"
			}
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
	return nil, "", close, noLocalKeys(fmt.Sprintf("%s is owned by SSH key %s, which this machine doesn't have (%s); pass --identity PATH or ssh-add the key",
		name, ssh.FingerprintSHA256(public), strings.Join(append(skipped, agentState), "; ")))
}
