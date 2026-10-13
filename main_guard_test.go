package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the trust store at a throwaway file so no test can ever
// read or write the developer's real ~/.tinfoil/known-configs.yml. Individual
// tests override the same variable with t.Setenv for their own fixtures.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tinfoil-cli-tests-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv(envKnownConfigs, filepath.Join(dir, "known-configs.yml")); err != nil {
		os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
