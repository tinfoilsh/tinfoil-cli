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
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const maxOwnerCredentialBytes = 4096

// Owner signing and storage encryption use independent keys.
type ownerCredential struct {
	Version     int    `json:"version"`
	Key         []byte `json:"key"`
	SigningSeed []byte `json:"signing_seed,omitempty"`
	Owner       string `json:"owner_public_key,omitempty"`
}

func readOwnerCredential(path string) (*ownerCredential, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOwnerCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > maxOwnerCredentialBytes {
		return nil, fmt.Errorf("owner credential %s exceeds 4096 bytes", path)
	}
	trimmed := bytes.TrimSpace(raw)
	key := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	defer clear(key)
	if n, err := base64.StdEncoding.Strict().Decode(key, trimmed); err == nil {
		if n == 32 || n == 64 {
			return nil, errors.New("legacy encryption-only key; this CLI requires an owner SSH credential. Keep this file for the existing deployment and use a new name for a fresh deployment")
		}
	}
	var credential ownerCredential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return nil, errors.New("invalid owner SSH credential JSON; restore the original credential file")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || len(credential.Key) != 32 || !(credential.Version == 2 && len(credential.SigningSeed) == ed25519.SeedSize || credential.Version == 3 && credential.Owner != "" && len(credential.SigningSeed) == 0) {
		return nil, errors.New("invalid owner credential version or keys; restore the original credential file")
	}
	return &credential, nil
}

func (c *ownerCredential) clear() { clear(c.Key); clear(c.SigningSeed) }

func saveOwnerCredential(path string, credential *ownerCredential) error {
	old, err := readOwnerCredential(path)
	if err == nil {
		defer old.clear()
		if !bytes.Equal(old.Key, credential.Key) || !bytes.Equal(old.SigningSeed, credential.SigningSeed) || old.Owner != credential.Owner {
			return fmt.Errorf("%s already holds a different credential; refusing to replace it: %w", path, os.ErrExist)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}
	defer clear(data)
	return writeStorageFile(path, data, true)
}

func (c *ownerCredential) publicKey() string {
	if c.Version == 3 {
		return c.Owner
	}
	if len(c.SigningSeed) != ed25519.SeedSize {
		return ""
	}
	private := ed25519.NewKeyFromSeed(c.SigningSeed)
	defer clear(private)
	return "ed25519:" + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
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
	config, err := configPath()
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(scope)
	root, accountID := filepath.Join(filepath.Dir(config), "resources"), storageHash(data)
	accountDir, err := existingCredentialDir(root, accountID)
	if err != nil {
		return "", err
	}
	if accountDir == "" {
		accountDir = filepath.Join(root, accountDirectoryLabel(scope)+"-"+accountID)
	}
	dir, err := existingCredentialDir(accountDir, id)
	if err != nil || dir != "" {
		return dir, err
	}
	name, err = sandboxName(name)
	if err != nil {
		// Readable labels are optional, including on the first connection.
		return filepath.Join(accountDir, id), nil
	}
	return filepath.Join(accountDir, name+"-"+id), nil
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

func resourceDirMatches(name, id string) bool {
	return looksLikeUUID(id) && (name == id || strings.HasSuffix(name, "-"+id))
}

// Existing Monitor credentials stay in place; sandbox credentials use resource UUIDs.
func credentialDir(scope accountScope, row containerView) (string, error) {
	if row.Repo != monitorRepo || !looksLikeUUID(row.ID) {
		return resourceDir(scope, row.ID, row.Name)
	}
	config, err := configPath()
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(scope)
	root := filepath.Join(filepath.Dir(config), "monitors", storageHash(data))
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	name, _ := sandboxName(row.Name)
	var legacy string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(root, entry.Name())
		var profile monitorProfile
		if err := readStorageJSON(filepath.Join(candidate, monitorProfileFile), &profile); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("read legacy Monitor profile %s: %w", candidate, err)
		}
		// Profiles without an ID retain their domain/name lookup.
		switch {
		case profile.ContainerID == row.ID:
		case profile.ContainerID == "" && (entry.Name() == name || profile.Domain != "" && profile.Domain == row.Domain):
		default:
			continue
		}
		if legacy != "" {
			return "", fmt.Errorf("multiple legacy Monitor credential directories for %s: %s and %s; restore a single original credential directory", row.ID, legacy, candidate)
		}
		legacy = candidate
	}
	if legacy != "" {
		return legacy, nil
	}
	return resourceDir(scope, row.ID, row.Name)
}

// A public identity file selects an ssh-agent key without copying its private key.
func ownerSigner(c *ownerCredential, dir string) (ssh.Signer, string, func(), error) {
	close := func() {}
	if len(c.SigningSeed) == ed25519.SeedSize {
		path := filepath.Join(dir, sandboxSSHKeyName)
		signer, err := ensureSSHIdentity(path, c.SigningSeed)
		return signer, path, close, err
	}
	public, err := measuredOwner(c.Owner)
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
	return nil, "", close, fmt.Errorf("owner %s requires its Ed25519 key through --identity or ssh-agent", ssh.FingerprintSHA256(public))
}

func resourceCredential(dir, file, owner string, known bool) (*ownerCredential, error) {
	if _, err := measuredOwner(owner); err != nil {
		return nil, err
	}
	c, err := readOwnerCredential(filepath.Join(dir, file))
	if errors.Is(err, os.ErrNotExist) && !known {
		c = &ownerCredential{Version: 3, Owner: owner, Key: make([]byte, 32)}
		defer c.clear()
		rand.Read(c.Key)
		if err = prepareStorageDirectory(dir); err != nil {
			return nil, err
		}
		err = saveOwnerCredential(filepath.Join(dir, file), c)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Back up the encryption credentials in %s. Your SSH key alone cannot recover this resource.\n", dir)
		}
		if err == nil || errors.Is(err, os.ErrExist) {
			c, err = readOwnerCredential(filepath.Join(dir, file))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("restore encryption credentials in %s: %w", dir, err)
	}
	if c.publicKey() != owner {
		c.clear()
		return nil, errors.New("measured owner changed")
	}
	return c, nil
}

// A workspace keeps its encryption key when it moves to a new sandbox. Look
// only in this account's saved resource records; never reuse the old VM identity.
func sandboxWorkspaceCredential(dir string, resource sandboxResource, known bool) (*ownerCredential, error) {
	path := filepath.Join(dir, sandboxDiskKeyName)
	if _, err := os.Stat(path); known || !errors.Is(err, os.ErrNotExist) {
		return resourceCredential(dir, sandboxDiskKeyName, resource.Owner, known)
	}
	accountDir := filepath.Dir(dir)
	volumeID, owner := resource.Volumes["workspace"], resource.Owner
	if !looksLikeUUID(volumeID) {
		return nil, errors.New("invalid workspace volume UUID")
	}
	entries, err := os.ReadDir(accountDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	found := new(ownerCredential)
	defer found.clear()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		savedDir := filepath.Join(accountDir, entry.Name())
		var saved sandboxResource
		if readStorageJSON(filepath.Join(savedDir, "resource.json"), &saved) != nil || !resourceDirMatches(entry.Name(), saved.ID) || saved.Volumes["workspace"] != volumeID {
			continue
		}
		if saved.Owner != owner {
			return nil, fmt.Errorf("workspace volume %s was used with a different owner; create the sandbox with its original owner public key", volumeID)
		}
		credential, err := readOwnerCredential(filepath.Join(savedDir, sandboxDiskKeyName))
		if err != nil {
			return nil, fmt.Errorf("restore the original workspace encryption credentials in %s: %w", savedDir, err)
		}
		if credential.publicKey() != owner || len(found.Key) != 0 && !bytes.Equal(found.Key, credential.Key) {
			credential.clear()
			return nil, fmt.Errorf("conflicting saved encryption credentials for workspace volume %s; restore the original credentials", volumeID)
		}
		if len(found.Key) != 0 {
			credential.clear()
		} else {
			*found = *credential
		}
	}
	if len(found.Key) != 0 {
		if err := prepareStorageDirectory(dir); err != nil {
			return nil, err
		}
		if err := saveOwnerCredential(path, found); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Reusing the saved encryption key for workspace volume %s. Back up the credentials in %s.\n", volumeID, dir)
	}
	return resourceCredential(dir, sandboxDiskKeyName, owner, len(found.Key) != 0)
}
