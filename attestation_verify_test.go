package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//func TestAttestationVerifyNitro(t *testing.T) {
//	args := []string{
//		"attestation",
//		"verify",
//		"-e", "models.default.tinfoil.sh",
//		"-r", "tinfoilsh/default-models-nitro",
//	}
//	rootCmd.SetArgs(args)
//	assert.Nil(t, rootCmd.Execute())
//}

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
