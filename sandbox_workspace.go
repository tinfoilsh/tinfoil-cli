package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
	credential, err := findWorkspaceCredential(filepath.Dir(accountDir), resource.Volumes["workspace"], resource.Owner)
	if err != nil {
		return nil, err
	}
	if credential == nil {
		return resourceCredential(dir, sandboxDiskKeyName, resource.Owner, false)
	}
	defer credential.clear()
	if err := prepareStorageDirectory(dir); err != nil {
		return nil, err
	}
	if err := saveOwnerCredential(path, credential); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Reusing the saved encryption key for workspace volume %s. Back up the credentials in %s.\n", resource.Volumes["workspace"], dir)
	return resourceCredential(dir, sandboxDiskKeyName, resource.Owner, true)
}

func findWorkspaceCredential(accountDir, volumeID, owner string) (_ *ownerCredential, retErr error) {
	if !looksLikeUUID(volumeID) {
		return nil, errors.New("invalid workspace volume UUID")
	}
	entries, err := os.ReadDir(accountDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found *ownerCredential
	defer func() {
		if retErr != nil && found != nil {
			found.clear()
		}
	}()
	for _, entry := range entries {
		if !entry.IsDir() || !looksLikeUUID(entry.Name()) {
			continue
		}
		dir := filepath.Join(accountDir, entry.Name())
		var saved sandboxResource
		if readStorageJSON(filepath.Join(dir, "resource.json"), &saved) != nil || saved.ID != entry.Name() || saved.Volumes["workspace"] != volumeID {
			continue
		}
		if saved.Owner != owner {
			return nil, fmt.Errorf("workspace volume %s was used with a different owner; create the sandbox with its original owner public key", volumeID)
		}
		credential, err := readOwnerCredential(filepath.Join(dir, sandboxDiskKeyName))
		if err != nil {
			return nil, fmt.Errorf("restore the original workspace encryption credentials in %s: %w", dir, err)
		}
		if credential.publicKey() != owner || found != nil && !bytes.Equal(found.Key, credential.Key) {
			credential.clear()
			return nil, fmt.Errorf("conflicting saved encryption credentials for workspace volume %s; restore the original credentials", volumeID)
		}
		if found != nil {
			credential.clear()
		} else {
			found = credential
		}
	}
	return found, nil
}
