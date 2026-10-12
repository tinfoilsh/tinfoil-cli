package main

import (
	"bytes"
	"crypto/ed25519"
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
	if err := decoder.Decode(new(any)); err != io.EOF || len(credential.Key) != 32 || !(credential.Version == 2 && len(credential.SigningSeed) == ed25519.SeedSize || credential.Version == 3 && credential.Owner != "" && len(credential.SigningSeed) == 0) {
		return nil, errors.New("invalid owner credential version or keys; restore the original credential file")
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
	return bytes.Equal(a.Key, b.Key) && bytes.Equal(a.SigningSeed, b.SigningSeed) && a.Owner == b.Owner
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
