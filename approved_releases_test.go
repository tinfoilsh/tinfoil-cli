package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovedReleaseTemplatesNeedNoGitHubAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("default template unexpectedly fetched from %s", r.URL.Path)
		http.Error(w, "unavailable", 503)
	}))
	defer server.Close()
	sandbox, err := fetchSandboxTemplate(defaultSandboxTag, server.URL)
	require.NoError(t, err)
	require.Equal(t, "9b367406954fdb3242abec6802ea92dd02c38c2ea6d189fc0479d5e41760f032", storageHash(sandbox))
	name, value, err := ownerBinding(sandbox, sandboxOwnerEnv, sandboxArgonOwnerEnv)
	require.NoError(t, err)
	require.Equal(t, sandboxArgonOwnerEnv, name)
	require.Empty(t, value)
	rendered, err := renderTemplateEnv(sandbox, map[string]string{sandboxArgonOwnerEnv: testOwnerPHC})
	require.NoError(t, err)
	_, err = verifySandboxConfig(containerView{Config: string(rendered)}, testOwnerPHC, sandbox, nil)
	require.NoError(t, err)

	oldPath := monitorTemplatePath
	monitorTemplatePath = ""
	t.Cleanup(func() { monitorTemplatePath = oldPath })
	dir := t.TempDir()
	monitor, err := monitorTemplate(dir, defaultMonitorTag, server.URL)
	require.NoError(t, err)
	require.Equal(t, "80c640d7dd5e00ddfa601f25c57678d0ba71900796f5ec1bf141cda4a3400f8a", storageHash(monitor))
	name, value, err = ownerBinding(monitor, monitorOwnerEnv, monitorArgonOwnerEnv)
	require.NoError(t, err)
	require.Equal(t, monitorArgonOwnerEnv, name)
	require.Empty(t, value)
	_, err = verifyMonitorConfig(renderedMonitorConfig(string(monitor), testOwnerPHC), testOwnerPHC, monitor)
	require.NoError(t, err)
	// An explicit local template remains available for private development.
	monitorTemplatePath = filepath.Join(dir, "override.yml")
	require.NoError(t, os.WriteFile(monitorTemplatePath, []byte(testMonitorTemplate), 0600))
	override, err := monitorTemplate(dir, defaultMonitorTag, server.URL)
	require.NoError(t, err)
	require.Equal(t, []byte(testMonitorTemplate), override)
}
