package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"github.com/zalando/go-keyring"
)

const (
	credentialService   = "tinfoil-cli"
	credentialLockWait  = 45 * time.Second
	credentialLockRetry = 20 * time.Millisecond
)

type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

type OSKeyring struct{}

func (OSKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (OSKeyring) Set(service, user, secret string) error   { return keyring.Set(service, user, secret) }
func (OSKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

type Store struct {
	dir     string
	keyring Keyring
}

// NewStore does not access the filesystem or credential service.
func NewStore(dir string, keyring Keyring) *Store {
	return &Store{dir: dir, keyring: keyring}
}

type credentialSlot struct {
	Keyring bool            `json:"keyring"`
	Record  json.RawMessage `json:"record,omitempty"`
	Deleted bool            `json:"deleted,omitempty"`
}

func (s *Store) file(name string) string {
	return filepath.Join(s.dir, name+".json")
}

func (s *Store) readSlot(name string) (string, *credentialSlot, error) {
	path := s.file(name)
	var slot credentialSlot
	if err := statefile.ReadJSON(path, &slot); errors.Is(err, os.ErrNotExist) {
		return path, nil, nil
	} else if err != nil {
		return path, nil, fmt.Errorf("%s: %w", path, err)
	}
	return path, &slot, nil
}

func (s *Store) read(name string, out any) (bool, error) {
	_, slot, err := s.readSlot(name)
	if err != nil || slot == nil || slot.Deleted {
		return false, err
	}
	if slot.Record != nil {
		return true, json.Unmarshal(slot.Record, out)
	}
	secret, err := s.keyring.Get(credentialService, name)
	if err != nil {
		return false, fmt.Errorf("reading %s from the OS credential service: %w", name, err)
	}
	return true, json.Unmarshal([]byte(secret), out)
}

func (s *Store) write(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	path, previous, err := s.readSlot(name)
	if err != nil {
		return err
	}
	if err := statefile.PrepareDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if previous == nil || !previous.Keyring {
		marker := credentialSlot{Keyring: true, Deleted: previous == nil}
		if previous != nil {
			marker.Record = previous.Record
		}
		if err := writeCredentialSlot(path, marker); err != nil {
			return err
		}
	}
	slot := credentialSlot{Keyring: true}
	if s.keyring.Set(credentialService, name, string(data)) != nil {
		slot.Record = data
	}
	return writeCredentialSlot(path, slot)
}

func writeCredentialSlot(path string, slot credentialSlot) error {
	encoded, err := json.Marshal(slot)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return statefile.Write(path, encoded, false)
}

func (s *Store) delete(name string) error {
	path, slot, err := s.readSlot(name)
	if slot == nil && err == nil {
		return nil
	}
	if err != nil || slot.Keyring {
		if err := s.keyring.Delete(credentialService, name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return errors.Join(fmt.Errorf("%s is no longer used, but the OS credential service still holds a copy; rerun `tinfoil logout` when it is available: %w", name, err),
				writeCredentialSlot(path, credentialSlot{Keyring: true, Deleted: true}))
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) withLock(fn func() error) error {
	path := s.file("credentials")
	unlock, err := statefile.Lock(path)
	for deadline := time.Now().Add(credentialLockWait); errors.Is(err, statefile.ErrLocked) && time.Now().Before(deadline); {
		time.Sleep(credentialLockRetry)
		unlock, err = statefile.Lock(path)
	}
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
