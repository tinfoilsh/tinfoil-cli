package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationVerifySEV(t *testing.T) {
	args := []string{
		"attestation",
		"verify",
		"-e", "inference.tinfoil.sh",
		"-r", "tinfoilsh/confidential-inference-proxy",
	}
	rootCmd.SetArgs(args)
	assert.Nil(t, rootCmd.Execute())
}
