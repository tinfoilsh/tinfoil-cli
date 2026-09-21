package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func expectedRepository(ref string) (string, error) {
	return resolveRepository(&http.Client{Timeout: 30 * time.Second}, "https://github-proxy.tinfoil.sh", ref)
}

// Preserve the CLI's latest-release policy for a bare repository. The generic
// v3 SDK otherwise accepts any freshly endorsed release from that repository.
// Resolve via the release service, independently of the enclave's document.
// An explicit tag/digest is already caller policy and must never be replaced.
func resolveRepository(client *http.Client, baseURL, ref string) (string, error) {
	if strings.Contains(ref, "@") {
		return ref, nil
	}
	if !repositoryName.MatchString(ref) {
		return "", fmt.Errorf("invalid expected repository %q", ref)
	}
	get := func(path string) ([]byte, error) {
		response, err := client.Get(baseURL + path)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("release lookup: HTTP %d", response.StatusCode)
		}
		return io.ReadAll(io.LimitReader(response.Body, 1<<20))
	}
	data, err := get("/repos/" + ref + "/releases/latest")
	if err != nil {
		return "", fmt.Errorf("resolving expected release for %s: %w", ref, err)
	}
	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", fmt.Errorf("decoding expected release: %w", err)
	}
	if release.Tag == "" || strings.ContainsAny(release.Tag, "@ \t\n\r") {
		return "", fmt.Errorf("release service returned an invalid tag")
	}
	data, err = get("/" + ref + "/releases/download/" + url.PathEscape(release.Tag) + "/tinfoil.hash")
	if err != nil {
		return "", fmt.Errorf("resolving expected digest for %s: %w", ref, err)
	}
	digest := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("release service returned an invalid SHA-256 digest")
	}
	return ref + "@" + release.Tag + "@sha256:" + strings.ToLower(digest), nil
}
