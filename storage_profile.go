package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	storageDirMode        = 0o700
	storageFileMode       = 0o600
	storageSchemaVersion  = 1
	storagePhaseAllocated = "allocated"
	storagePhaseAttempted = "secret_create_attempted"
	storagePhaseStored    = "secret_stored"
	storagePhaseVerifying = "verifying_existing_secret"
	storagePhasePrepared  = "prepared"
)

var storageRepoPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)
var storageRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
var storageNamePattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
var storageDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type storageScope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id"`
	Repo            string `json:"repo"`
}

type storageProfile struct {
	Version      int          `json:"version"`
	Scope        storageScope `json:"scope"`
	KeyserverURL string       `json:"keyserver_url"`
	AWSRegion    string       `json:"aws_region"`
	AWSPrefix    string       `json:"aws_prefix"`
	AWSProfile   string       `json:"aws_profile,omitempty"`
	Domain       string       `json:"domain,omitempty"`
}

type storageReceipt struct {
	Version       int            `json:"version"`
	Profile       storageProfile `json:"profile"`
	VolumeID      string         `json:"volume_id"`
	Mount         string         `json:"mount"`
	KeySecret     string         `json:"key_secret"`
	SecretName    string         `json:"secret_name"`
	SecretARN     string         `json:"secret_arn,omitempty"`
	SecretVersion string         `json:"secret_version,omitempty"`
	Generated     bool           `json:"generated"`
	Phase         string         `json:"phase"`
	Tag           string         `json:"tag"`
	Domain        string         `json:"domain"`
	ConfigPath    string         `json:"config_path,omitempty"`
	ConfigHash    string         `json:"config_sha256,omitempty"`
	PolicyPath    string         `json:"policy_path,omitempty"`
	PolicyHash    string         `json:"policy_sha256,omitempty"`
}

func storageHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s storageScope) key() string {
	data, _ := json.Marshal(s)
	return storageHash(data)
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
	name := "profile-" + scope.key()
	if volume != "" {
		if !looksLikeUUID(volume) {
			return "", fmt.Errorf("volume ID must be a UUID")
		}
		name = "volume-" + scope.key() + "-" + strings.ToLower(volume)
	}
	return filepath.Join(dir, name+".json"), nil
}

func readStorageJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid storage metadata; restore it from a trusted backup")
	}
	return nil
}

func prepareStorageDirectory(dir string) error {
	if err := os.MkdirAll(dir, storageDirMode); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("storage directory must not be a symlink")
	}
	return os.Chmod(dir, storageDirMode)
}

func writeStorageJSON(path string, value any, exclusive bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding storage metadata: %w", err)
	}
	if err := prepareStorageDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("preparing storage directory: %w", err)
	}
	return writeStorageFile(path, append(data, '\n'), exclusive)
}

// The temporary file is synced before publication; exclusive publication
// prevents concurrent commands from replacing an existing custody record.
func writeStorageFile(path string, data []byte, exclusive bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".storage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if exclusive {
		err = os.Link(f.Name(), path)
	} else {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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
	return p, p.validate()
}

func (p storageProfile) validate() error {
	u, err := url.Parse(p.KeyserverURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return fmt.Errorf("--keyserver-url must be an HTTPS origin without credentials, query, or path")
	}
	if !storageRegionPattern.MatchString(p.AWSRegion) {
		return fmt.Errorf("--aws-region must be an explicit AWS region")
	}
	if p.AWSPrefix != "" && (!storageNamePattern.MatchString(p.AWSPrefix) || strings.Trim(p.AWSPrefix, "/") != p.AWSPrefix || len(p.AWSPrefix) > storageMaxPrefixLength) {
		return fmt.Errorf("--aws-prefix must be a Secrets Manager name prefix without leading/trailing slashes")
	}
	if p.Domain != "" {
		return validateStorageDomain(p.Domain)
	}
	return nil
}

func validateStorageDomain(domain string) error {
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return fmt.Errorf("an exact deployment DNS domain is required (no wildcard, URL, or port)")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 || !storageDomainLabel.MatchString(label) {
			return fmt.Errorf("an exact lowercase deployment DNS domain is required (no wildcard, URL, or port)")
		}
	}
	return nil
}

func resolveStorageScope(client *cpClient, identifier string) (storageScope, error) {
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
	u, err := url.Parse(client.baseURL)
	if err != nil {
		return storageScope{}, fmt.Errorf("invalid controlplane URL")
	}
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	return storageScope{ControlplaneURL: strings.TrimRight(u.String(), "/"), OrgID: identity.Organization.ID, Repo: canonical}, nil
}

func acquireStorageLock(path string) (func(), error) {
	if err := prepareStorageDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, storageFileMode)
	if err != nil {
		return nil, fmt.Errorf("storage operation is locked; after verifying no other command is running, remove %s.lock: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path + ".lock") }, nil
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
