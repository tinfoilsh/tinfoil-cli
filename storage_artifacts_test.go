package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const storageTestConfig = `# deployment comment
cpus: 2
memory: 8192
debug: false
future-setting: {enabled: true} # unknown stays
containers:
  - name: app
    image: ghcr.io/owner/app:latest
    args: ["-v", "/mnt/data:/data"] # mount stays
volumes:
  - name: data # disk stays
    mount: /mnt/data
    future-volume-setting: keep
`

func TestStorageConfigPreservesYAMLAndOriginalReference(t *testing.T) {
	r := testStorageReceipt()
	prepared, ref, err := prepareVolumeConfig([]byte(storageTestConfig), r.Profile.KeyserverURL, r.Mount, r.KeySecret, false)
	require.NoError(t, err)
	require.Equal(t, r.KeySecret, ref)
	for _, retained := range []string{"# deployment comment", "# unknown stays", "# mount stays", "# disk stays", "future-setting: {enabled: true}", "future-volume-setting: keep", "mount: /mnt/data"} {
		require.Contains(t, string(prepared), retained)
	}
	require.Contains(t, string(prepared), "keyserver-url: "+r.Profile.KeyserverURL)
	require.Contains(t, string(prepared), "key-secret: "+r.KeySecret)
	again, ref, err := prepareVolumeConfig(prepared, r.Profile.KeyserverURL, r.Mount, "DO_NOT_REPLACE", true)
	require.NoError(t, err)
	require.Equal(t, r.KeySecret, ref)
	require.Equal(t, prepared, again)
	_, _, err = prepareVolumeConfig(prepared, r.Profile.KeyserverURL, r.Mount, "NEW_KEY", false)
	require.ErrorContains(t, err, "refusing to overwrite")
	_, _, err = prepareVolumeConfig(prepared, "https://another.example.com", r.Mount, r.KeySecret, true)
	require.ErrorContains(t, err, "keyserver-url")
}

func TestStorageRejectsAmbiguousAndUnsafeConfig(t *testing.T) {
	for _, raw := range []string{
		"volumes: []\nvolumes: []\n",
		"volumes: []\n---\nvolumes: []\n",
		"base: &base {name: data}\nvolumes: [*base]\n",
		"base: &base {name: data}\nvolumes: [{<<: *base}]\n",
		"volumes: [{name: data}, {name: data}]\n",
		"volumes: [{name: other}]\n",
		"volumes: [{name: data, key-secret: null}]\n",
		"debug: true\nvolumes: [{name: data}]\n",
		"volumes: [{name: data, key-secret: ORIGINAL}, {name: other, key-secret: ORIGINAL}]\n",
	} {
		_, _, err := prepareVolumeConfig([]byte(raw), "https://keys.example.com", "data", "ORIGINAL", true)
		require.Error(t, err, raw)
	}
}

func TestStoragePolicyIsAdditiveAndPinsAllIdentities(t *testing.T) {
	r := testStorageReceipt()
	raw := []byte(`# private policy comment
future-policy-setting: keep
workloads:
  existing:
    repo: owner/repo
    tag: v1.2.3
    domain: app.example.com # domain stays
    secrets:
      APP_TOKEN: {path: app/token, field: value} # mapping stays
`)
	prepared, err := prepareVolumePolicy(raw, r, "volumes/"+r.VolumeID+"/key")
	require.NoError(t, err)
	for _, kept := range []string{"# private policy comment", "future-policy-setting: keep", "# domain stays", "# mapping stays", "APP_TOKEN: {path: app/token, field: value}"} {
		require.Contains(t, string(prepared), kept)
	}
	require.NotContains(t, string(prepared), "volume-"+r.VolumeID+":")
	again, err := prepareVolumePolicy(prepared, r, "volumes/"+r.VolumeID+"/key")
	require.NoError(t, err)
	require.Equal(t, prepared, again)
	_, err = prepareVolumePolicy(prepared, r, "replacement/key")
	require.ErrorContains(t, err, "refusing to overwrite")
	r.Domain = "other.example.com"
	_, err = prepareVolumePolicy(prepared, r, "volumes/"+r.VolumeID+"/key")
	require.ErrorContains(t, err, "only one domain per repo/tag")
}

func TestStoragePolicyRejectsMissingIdentityAndDuplicatePins(t *testing.T) {
	for _, field := range []string{"repo", "tag", "domain", "wildcard"} {
		r := testStorageReceipt()
		switch field {
		case "repo":
			r.Profile.Scope.Repo = ""
		case "tag":
			r.Tag = ""
		case "domain":
			r.Domain = ""
		case "wildcard":
			r.Domain = "*.example.com"
		}
		_, err := prepareVolumePolicy(nil, r, "volume/key")
		require.Error(t, err)
	}
	r := testStorageReceipt()
	w := "{repo: owner/repo, tag: v1.2.3, domain: app.example.com, secrets: {KEY: {path: old/key, field: value}}}"
	for _, raw := range []string{
		"workloads: {one: " + w + ", two: " + w + "}",
		strings.Replace("workloads: {one: "+w+"}", "domain: app.example.com, ", "", 1),
		strings.Replace("workloads: {one: "+w+"}", "domain: app.example.com", "domain: '*.example.com'", 1),
		"workloads: {one: {repo: owner/repo, tag: v1, domain: app.example.com, secrets: {}}}",
	} {
		_, err := prepareVolumePolicy([]byte(raw), r, "volume/key")
		require.Error(t, err, raw)
	}
}

func TestStorageOutputsNeverClobberFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prepared.yml")
	require.NoError(t, writeStorageArtifact(path, []byte("original\n")))
	require.NoError(t, writeStorageArtifact(path, []byte("original\n")))
	require.Error(t, writeStorageArtifact(path, []byte("replacement\n")))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original\n", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, storageFileMode, info.Mode().Perm())
}
