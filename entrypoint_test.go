package main_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	entrypointVersion  = "99.0.0"
	entrypointAdminKey = "admin_entrypoint_test"
	entrypointTimeout  = 10 * time.Second
)

func TestEntrypointPreservesLinkerSettingsAndUserAgents(t *testing.T) {
	home := t.TempDir()
	binary := filepath.Join(home, "tinfoil")
	build := exec.Command("go", "build", "-ldflags", "-X main.version="+entrypointVersion+" -X main.clerkCLIClientID=invalid!", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building root executable: %v\n%s", err, output)
	}
	var environment []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "TINFOIL_") || name == "HOME" || name == "USERPROFILE" || name == "SSH_AUTH_SOCK" || name == "PATH" {
			continue
		}
		environment = append(environment, entry)
	}
	for _, opener := range []string{"open", "xdg-open"} {
		if err := os.WriteFile(filepath.Join(home, opener), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	environment = append(environment, "HOME="+home, "USERPROFILE="+home, "PATH="+home, "TINFOIL_NO_UPDATE_CHECK=1")
	run := func(extra []string, args ...string) (string, string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), entrypointTimeout)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = append(append([]string{}, environment...), extra...)
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		err := command.Run()
		return output.String(), diagnostic.String(), err
	}
	output, diagnostic, err := run(nil, "--version")
	if err != nil || output != "tinfoil version "+entrypointVersion+"\n" || diagnostic != "" {
		t.Fatalf("version: %v, stdout=%q, stderr=%q", err, output, diagnostic)
	}
	_, diagnostic, err = run(nil, "login")
	if err == nil || !strings.Contains(diagnostic, "Clerk sign-in is not configured") {
		t.Fatalf("auth linker setting was not applied: %v, stderr=%q", err, diagnostic)
	}
	controlplane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/domains" || r.Header.Get("Authorization") != "Bearer "+entrypointAdminKey || r.UserAgent() != "tinfoil-cli/"+entrypointVersion {
			t.Errorf("unexpected controlplane request: %s %s, authorization=%q, user-agent=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"), r.UserAgent())
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		io.WriteString(w, "[]")
	}))
	t.Cleanup(controlplane.Close)
	output, diagnostic, err = run([]string{"TINFOIL_ADMIN_KEY=" + entrypointAdminKey, "TINFOIL_CONTROLPLANE_URL=" + controlplane.URL}, "domain", "list", "--output", "json")
	if err != nil || strings.TrimSpace(output) != "[]" || diagnostic != "" {
		t.Fatalf("controlplane version: %v, stdout=%q, stderr=%q", err, output, diagnostic)
	}
}
