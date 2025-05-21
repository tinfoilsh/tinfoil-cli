package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationVerifySEV(t *testing.T) {
	args := []string{
		"attestation",
		"verify",
		"-e", "deepseek-r1-70b-p.model.tinfoil.sh",
		"-r", "tinfoilsh/confidential-deepseek-r1-70b-prod",
	}
	rootCmd.SetArgs(args)
	assert.Nil(t, rootCmd.Execute())
}
