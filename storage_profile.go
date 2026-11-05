package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const (
	storageDirMode        = 0o700
	storageFileMode       = 0o600
	storageSchemaVersion  = autounlock.SchemaVersion
	storagePhaseAllocated = autounlock.PhaseAllocated
	storagePhaseAttempted = autounlock.PhaseAttempted
	storagePhaseStored    = autounlock.PhaseStored
	storagePhaseVerifying = autounlock.PhaseVerifying
	storagePhasePrepared  = autounlock.PhasePrepared
)

var storageRepoPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)
var storageNamePattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
var errStorageLocked = statefile.ErrLocked

type storageScope = autounlock.Scope
type storageProfile = autounlock.Profile
type storageReceipt = autounlock.Receipt

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

func storageMetadataPath(scope storageScope, volume string) (string, error) {
	dir, err := storageDirectory()
	if err != nil {
		return "", err
	}
	name := "profile-" + scope.Key()
	if volume != "" {
		if !looksLikeUUID(volume) {
			return "", fmt.Errorf("volume ID must be a UUID")
		}
		name = "volume-" + scope.Key() + "-" + strings.ToLower(volume)
	}
	return filepath.Join(dir, name+".json"), nil
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

func probeStorageDirectory(dir string) error {
	return statefile.ProbeDirectory(dir)
}

func writeStorageFile(path string, data []byte, exclusive bool) error {
	return statefile.Write(path, data, exclusive)
}

func loadStorageProfile(scope storageScope) (storageProfile, error) {
	path, err := storageMetadataPath(scope, "")
	if err != nil {
		return storageProfile{}, err
	}
	var p storageProfile
	if err := readStorageJSON(path, &p); err != nil {
		return p, err
	}
	if p.Version != storageSchemaVersion || p.Scope != scope {
		return p, fmt.Errorf("storage profile scope/version mismatch")
	}
	return p, p.Validate()
}

func validateStorageDomain(domain string) error {
	return autounlock.ValidateDomain(domain)
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

func loadStorageReceipt(scope storageScope, volume string) (storageReceipt, error) {
	path, err := storageMetadataPath(scope, volume)
	if err != nil {
		return storageReceipt{}, err
	}
	var r storageReceipt
	if err := readStorageJSON(path, &r); err != nil {
		return r, err
	}
	if r.Version != storageSchemaVersion || r.Profile.Scope != scope || r.VolumeID != volume {
		return r, errors.New("storage receipt scope/version mismatch")
	}
	return r, nil
}
