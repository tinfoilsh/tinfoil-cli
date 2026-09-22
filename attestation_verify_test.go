package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationVerifySEV(t *testing.T) {
	if os.Getenv("RUN_TINFOIL_INTEGRATION") != "true" {
		t.Skip("set RUN_TINFOIL_INTEGRATION=true for live attestation")
	}
	args := []string{
		"attestation",
		"verify",
		"-e", "inference.tinfoil.sh",
		"-r", "tinfoilsh/confidential-model-router",
	}
	rootCmd.SetArgs(args)
	assert.Nil(t, rootCmd.Execute())
}

func TestVerificationError(t *testing.T) {
	cases := []struct {
		status  string
		wantErr bool
	}{
		{"ok", false},
		{"enclave_only", true},
		{"fail", true},
		{"FAILED", true},
	}
	for _, c := range cases {
		record := &auditRecord{Status: c.status, Error: "PCR register mismatch"}
		err := record.verificationError()
		if c.wantErr {
			assert.ErrorContains(t, err, "verification failed")
		} else {
			assert.Nil(t, err)
		}
	}
}
