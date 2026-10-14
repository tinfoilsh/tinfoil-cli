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

type monitorBinding struct {
	ContainerID string `json:"container_id"`
	Owner       string `json:"owner_public_key"`
}

func sandboxMonitorBinding(env map[string]string) (monitorBinding, error) {
	var binding monitorBinding
	if json.Unmarshal([]byte(env["MONITOR_BINDING"]), &binding) != nil || !looksLikeUUID(binding.ContainerID) || binding.Owner == "" {
		return binding, errors.New("sandbox has no measured Monitor binding")
	}
	return binding, nil
}

func measuredOwner(value string) (ssh.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || !strings.HasPrefix(value, "ed25519:") || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("workload requires a measured Ed25519 owner public key")
	}
	return ssh.NewPublicKey(ed25519.PublicKey(raw))
}

func resourceDir(scope accountScope, id string) (string, error) {
	if !looksLikeUUID(id) {
		return "", errors.New("invalid resource UUID")
	}
	config, err := configPath()
	data, _ := json.Marshal(scope)
	return filepath.Join(filepath.Dir(config), "resources", storageHash(data), id), err
}

// Existing credentials stay in place. Callers use the same loader regardless
// of credential version or whether this resource predates UUID directories.
// For a sandbox, monitorName must come from its resolved measured Monitor binding.
func credentialDir(scope accountScope, row containerView, monitorName string) (string, error) {
	dir, err := resourceDir(scope, row.ID)
	if err != nil {
		return "", err
	}
	name, err := sandboxName(row.Name)
	if err != nil {
		return "", err
	}
	config, err := configPath()
	if err != nil {
		return "", err
	}
	switch row.Repo {
	case monitorRepo:
		data, _ := json.Marshal(scope)
		legacy := filepath.Join(filepath.Dir(config), "monitors", storageHash(data), name)
		if _, err := os.Stat(filepath.Join(legacy, monitorProfileFile)); err == nil {
			return legacy, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	case defaultSandboxRepo:
		legacy := filepath.Join(filepath.Dir(config), "sandboxes", name)
		var binding struct {
			Scope   accountScope `json:"scope"`
			Monitor string       `json:"monitor"`
		}
		if err := readStorageJSON(filepath.Join(legacy, "monitor.json"), &binding); err == nil {
			if binding.Scope == scope {
				if binding.Monitor == "" || binding.Monitor != monitorName {
					return "", errors.New("saved sandbox Monitor binding does not match the measured Monitor")
				}
				return legacy, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return dir, nil
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
func sandboxWorkspaceCredential(scope accountScope, dir string, resource sandboxResource, known bool) (*ownerCredential, error) {
	path := filepath.Join(dir, sandboxDiskKeyName)
	if _, err := os.Stat(path); known || !errors.Is(err, os.ErrNotExist) {
		return resourceCredential(dir, sandboxDiskKeyName, resource.Owner, known)
	}
	accountDir, err := resourceDir(scope, resource.ID)
	if err != nil {
		return nil, err
	}
	volumeID, owner := resource.Volumes["workspace"], resource.Owner
	if !looksLikeUUID(volumeID) {
		return nil, errors.New("invalid workspace volume UUID")
	}
	entries, err := os.ReadDir(filepath.Dir(accountDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	found := new(ownerCredential)
	defer found.clear()
	for _, entry := range entries {
		if !entry.IsDir() || !looksLikeUUID(entry.Name()) {
			continue
		}
		savedDir := filepath.Join(filepath.Dir(accountDir), entry.Name())
		var saved sandboxResource
		if readStorageJSON(filepath.Join(savedDir, "resource.json"), &saved) != nil || saved.ID != entry.Name() || saved.Volumes["workspace"] != volumeID {
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
