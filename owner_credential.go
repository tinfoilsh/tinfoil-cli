package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxOwnerCredentialBytes = 4096

// Owner signing and storage encryption use independent keys.
type ownerCredential struct {
	Version     int    `json:"version"`
	Key         []byte `json:"key"`
	SigningSeed []byte `json:"signing_seed"`
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
	credential, err := decodeOwnerCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("owner credential %s: %w", path, err)
	}
	return credential, nil
}

func (c *ownerCredential) clear() { clear(c.Key); clear(c.SigningSeed) }

func decodeOwnerCredential(raw []byte) (*ownerCredential, error) {
	if key, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(raw))); err == nil {
		defer clear(key)
		if len(key) == 32 || len(key) == 64 {
			return nil, errors.New("legacy encryption-only key; this CLI requires an owner SSH credential. Keep this file for the existing deployment and use a new name for a fresh deployment")
		}
	}
	var credential ownerCredential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return nil, errors.New("invalid owner SSH credential JSON; restore the original credential file")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || credential.Version != 2 || len(credential.Key) != 32 || len(credential.SigningSeed) != ed25519.SeedSize {
		return nil, errors.New("owner SSH credential requires version 2 and separate 32-byte key and signing_seed fields; restore the original credential file")
	}
	return &credential, nil
}

func saveOwnerCredential(path string, credential *ownerCredential) error {
	old, err := readOwnerCredential(path)
	if err == nil {
		defer old.clear()
		if !sameOwnerCredential(old, credential) {
			return fmt.Errorf("%s already holds a different credential; refusing to replace it", path)
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
	return writeNewFile(path, data)
}

func sameOwnerCredential(a, b *ownerCredential) bool {
	return bytes.Equal(a.Key, b.Key) && bytes.Equal(a.SigningSeed, b.SigningSeed)
}

func newSigningCredential() (*ownerCredential, error) {
	c := &ownerCredential{Version: 2, Key: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	if _, err := rand.Read(c.Key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(c.SigningSeed); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ownerCredential) publicKey() string {
	if len(c.SigningSeed) != ed25519.SeedSize {
		return ""
	}
	private := ed25519.NewKeyFromSeed(c.SigningSeed)
	defer clear(private)
	return "ed25519:" + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
}

// Existing deployments must keep their signing and storage keys.
func createOwnerCredential(path string, exists bool) (*ownerCredential, string, error) {
	credential, err := readOwnerCredential(path)
	if errors.Is(err, os.ErrNotExist) {
		if exists {
			return nil, "", errors.New("existing resource has no local owner credential")
		}
		credential, err = newSigningCredential()
	}
	if err != nil {
		return nil, "", err
	}
	return credential, credential.publicKey(), nil
}
