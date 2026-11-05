package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const (
	storageDirMode       = 0o700
	storageFileMode      = 0o600
	storageSchemaVersion = autounlock.SchemaVersion
)

var storageRepoPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)
var errStorageLocked = statefile.ErrLocked

type storageScope = autounlock.Scope
type storageProfile = autounlock.Profile
type storageReceipt = autounlock.Receipt
type storageArtifactOptions = autounlock.ArtifactOptions
type volumeKeyStore = autounlock.KeyStore

func storageHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func storageDirectory() (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "storage"), nil
}

func newStorageService() (*autounlock.Service, error) {
	dir, err := storageDirectory()
	if err != nil {
		return nil, err
	}
	return autounlock.NewService(dir, os.Stdin), nil
}

func readStorageJSON(path string, out any) error {
	return statefile.ReadJSON(path, out)
}

func prepareStorageDirectory(dir string) error {
	return statefile.PrepareDirectory(dir)
}

func writeStorageJSON(path string, value any, exclusive bool) error {
	return statefile.WriteJSON(path, value, exclusive)
}

func writeStorageFile(path string, data []byte, exclusive bool) error {
	return statefile.Write(path, data, exclusive)
}

func resolveStorageScope(client *cpClient, identifier string) (storageScope, error) {
	u, err := url.Parse(client.baseURL)
	if err != nil {
		return storageScope{}, fmt.Errorf("invalid controlplane URL")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return storageScope{}, fmt.Errorf("storage controlplane URL must not contain credentials, query, or fragment")
	}
	var identity authContext
	if _, err := client.do("GET", "/api/auth/context", nil, nil, &identity); err != nil {
		return storageScope{}, err
	}
	if identity.ContextType != "organization" || identity.Organization == nil || identity.Organization.ID == "" || identity.UserID == "" {
		return storageScope{}, fmt.Errorf("project storage requires a verified organization login")
	}
	if !strings.Contains(identifier, "/") {
		p, err := resolveProject(client, identifier)
		if err != nil {
			return storageScope{}, err
		}
		identifier = p.Repo
	}
	canonical := strings.ToLower(strings.TrimSpace(identifier))
	ref, err := parseRepository(canonical)
	if err != nil || !storageRepoPattern.MatchString(canonical) {
		return storageScope{}, fmt.Errorf("project must identify a valid owner/repo or existing project ID")
	}
	var response repoConfigResponse
	if _, err := client.do("GET", ref.apiPath()+"/config", nil, nil, &response); err != nil {
		return storageScope{}, err
	}
	if !response.Success {
		return storageScope{}, fmt.Errorf("repository access was not confirmed")
	}
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	return storageScope{ControlplaneURL: strings.TrimRight(u.String(), "/"), OrgID: identity.Organization.ID, Repo: canonical}, nil
}

func acquireStorageLock(path string) (func(), error) {
	return statefile.Lock(path)
}
