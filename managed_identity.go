package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

type monitorBinding struct {
	ContainerID string `json:"container_id"`
	Owner       string `json:"owner_public_key"`
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
		if err := ensureOwnerSSHKey(path, c.SigningSeed); err != nil {
			return nil, "", close, err
		}
		signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(c.SigningSeed))
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
		if errors.As(parseErr, &encrypted) && encrypted.PublicKey != nil && sameSSHKey(string(ssh.MarshalAuthorizedKey(encrypted.PublicKey)), string(ssh.MarshalAuthorizedKey(public))) {
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
		if parseErr == nil && sameSSHKey(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), string(ssh.MarshalAuthorizedKey(public))) {
			return signer, path, close, nil
		}
	}
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		conn, dialErr := net.Dial("unix", socket)
		if dialErr == nil {
			signers, _ := agent.NewClient(conn).Signers()
			for _, signer := range signers {
				if sameSSHKey(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), string(ssh.MarshalAuthorizedKey(public))) {
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
		if _, err = rand.Read(c.Key); err != nil {
			return nil, err
		}
		if err = prepareStorageDirectory(dir); err != nil {
			return nil, err
		}
		err = saveOwnerCredential(filepath.Join(dir, file), c)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Back up the encryption credentials in %s. Your SSH key alone cannot recover this resource.\n", dir)
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
