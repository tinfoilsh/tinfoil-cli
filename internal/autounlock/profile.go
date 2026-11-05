// Package autounlock prepares customer-owned volume keys and their release artifacts.
package autounlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	SchemaVersion   = 1
	PhaseAllocated  = "allocated"
	PhaseAttempted  = "secret_create_attempted"
	PhaseStored     = "secret_stored"
	PhaseVerifying  = "verifying_existing_secret"
	PhasePrepared   = "prepared"
	maxPort         = 65535
	maxPrefixLength = 400
)

var storageRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
var storageNamePattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
var storageDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type Scope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id"`
	Repo            string `json:"repo"`
}

type Profile struct {
	Version      int    `json:"version"`
	Scope        Scope  `json:"scope"`
	KeyserverURL string `json:"keyserver_url"`
	AWSRegion    string `json:"aws_region"`
	AWSPrefix    string `json:"aws_prefix"`
	AWSProfile   string `json:"aws_profile,omitempty"`
	Domain       string `json:"domain,omitempty"`
}

type Receipt struct {
	Version       int     `json:"version"`
	Profile       Profile `json:"profile"`
	VolumeID      string  `json:"volume_id"`
	Mount         string  `json:"mount"`
	KeySecret     string  `json:"key_secret"`
	SecretName    string  `json:"secret_name"`
	SecretARN     string  `json:"secret_arn,omitempty"`
	SecretVersion string  `json:"secret_version,omitempty"`
	Generated     bool    `json:"generated"`
	Phase         string  `json:"phase"`
	Tag           string  `json:"tag"`
	Domain        string  `json:"domain"`
	ConfigPath    string  `json:"config_path,omitempty"`
	ConfigHash    string  `json:"config_sha256,omitempty"`
	PolicyPath    string  `json:"policy_path,omitempty"`
	PolicyHash    string  `json:"policy_sha256,omitempty"`
}

func storageHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s Scope) Key() string {
	data, _ := json.Marshal(s)
	return storageHash(data)
}

func (p Profile) Validate() error {
	u, err := url.Parse(p.KeyserverURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(p.KeyserverURL, "#") || u.Path != "" && u.Path != "/" {
		return fmt.Errorf("--keyserver-url must be an HTTPS origin without credentials, query, or path")
	}
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.Is6() {
			return fmt.Errorf("--keyserver-url has an invalid IPv6 host")
		}
	} else if strings.ContainsAny(u.Hostname(), "[]:") {
		return fmt.Errorf("--keyserver-url has an invalid host")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > maxPort {
			return fmt.Errorf("--keyserver-url has an invalid port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("--keyserver-url has an invalid port")
	}
	if !storageRegionPattern.MatchString(p.AWSRegion) {
		return fmt.Errorf("--aws-region must be an explicit AWS region")
	}
	if p.AWSPrefix != "" && (!storageNamePattern.MatchString(p.AWSPrefix) || strings.Trim(p.AWSPrefix, "/") != p.AWSPrefix || len(p.AWSPrefix) > maxPrefixLength) {
		return fmt.Errorf("--aws-prefix must be a Secrets Manager name prefix without leading/trailing slashes")
	}
	if p.Domain != "" {
		return ValidateDomain(p.Domain)
	}
	return nil
}

func ValidateDomain(domain string) error {
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
