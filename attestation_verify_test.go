package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestMeasurementJSONPreservesRegisterSchema(t *testing.T) {
	encoded := strings.Repeat("ab", measurement.RegisterSize)
	register, err := measurement.ParseRegister(encoded)
	require.NoError(t, err)
	for _, test := range []struct {
		expected measurement.Expected
		json     string
	}{
		{measurement.ExpectedSEVSNP{Launch: &register}, fmt.Sprintf(`{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":[%q]}`, encoded)},
		{measurement.ExpectedTDX{RTMR2: &register}, fmt.Sprintf(`{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","",%q,""]}`, encoded)},
	} {
		data, err := json.Marshal(measurementRecord(test.expected))
		require.NoError(t, err)
		require.JSONEq(t, test.json, string(data))
	}
}

func TestAttestationVerifySEV(t *testing.T) {
	commandState := newCommandFixture()

	if os.Getenv("RUN_TINFOIL_INTEGRATION") != "true" {
		t.Skip("set RUN_TINFOIL_INTEGRATION=true for live attestation")
	}
	args := []string{
		"attestation",
		"verify",
		"-e", "inference.tinfoil.sh",
		"-r", "tinfoilsh/confidential-model-router",
	}
	commandState.rootCmd.SetArgs(args)
	assert.Nil(t, commandState.rootCmd.Execute())
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
