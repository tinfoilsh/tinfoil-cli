package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationVerifyNitro(t *testing.T) {
	args := []string{
		"attestation",
		"verify",
		"-e", "models.default.tinfoil.sh",
		"-r", "tinfoilanalytics/default-models-nitro",
	}
	rootCmd.SetArgs(args)
	assert.Nil(t, rootCmd.Execute())
}

func TestAttestationVerifySEV(t *testing.T) {
	args := []string{
		"attestation",
		"verify",
		"-e", "inference.delta.tinfoil.sh",
		"-r", "tinfoilanalytics/provably-private-deepseek-r1",
	}
	rootCmd.SetArgs(args)
	assert.Nil(t, rootCmd.Execute())
}
