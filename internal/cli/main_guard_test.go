package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMain points the trust store at a throwaway file so no test can ever
// read or write the developer's real ~/.tinfoil/known-configs.json. Individual
// tests override the same variable with t.Setenv for their own fixtures. The
// in-memory keyring keeps tests away from the OS credential service.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Unsetenv(envTrust)
	dir, err := os.MkdirTemp("", "tinfoil-cli-tests-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv(envKnownConfigs, filepath.Join(dir, "known-configs.json")); err != nil {
		os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
