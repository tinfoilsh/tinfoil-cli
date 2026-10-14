package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gateEnv points the store at a temp file and returns its path.
func gateEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-configs.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(envKnownConfigs, path)
	return path
}

func TestGateDangerousBypassesAndRecordsNothing(t *testing.T) {
	path := gateEnv(t, "")
	var out strings.Builder
	source := "evil/api@r1@" + testDigestA
	if err := gateConnectionPolicy(source, strings.NewReader(""), &out, false, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "DANGEROUS") {
		t.Fatalf("dangerous mode must announce itself: %q", out.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("dangerous mode must not create or write the store")
	}
}

func TestGateMatchedJournalsNewPin(t *testing.T) {
	path := gateEnv(t, `{"allow":{"projects":["acme/api"]}}`)
	var out strings.Builder
	source := "acme/api@r42@" + testDigestA
	if err := gateConnectionPolicy(source, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "New config journaled: "+source) {
		t.Fatalf("expected journal announcement: %q", out.String())
	}
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.hasPin(source) {
		t.Fatalf("pin not journaled: %+v", policy)
	}

	// Second connect to the same config: quiet, no duplicate.
	out.Reset()
	if err := gateConnectionPolicy(source, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "New config journaled") {
		t.Fatalf("known pin must not re-announce: %q", out.String())
	}
}

func TestGateFrozenFailsClosed(t *testing.T) {
	gateEnv(t, `{"mode":"frozen","allow":{"projects":["acme/api"]}}`)
	err := gateConnectionPolicy("evil/api@r1@"+testDigestA, strings.NewReader("y\n"), &strings.Builder{}, true, false)
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("expected frozen failure, got %v", err)
	}
}

func TestGateFrozenStillAllowsMatchesAndNeverWrites(t *testing.T) {
	content := `{"mode":"frozen","allow":{"projects":["acme/api"]}}`
	path := gateEnv(t, content)
	var out strings.Builder
	if err := gateConnectionPolicy("acme/api@r1@"+testDigestA, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not journaled, mode: frozen") {
		t.Fatalf("first sight should still be announced: %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("frozen mode must never write the file:\n%s", data)
	}
}

func TestGateNonInteractiveFailsClosed(t *testing.T) {
	gateEnv(t, "")
	err := gateConnectionPolicy("acme/api@r1@"+testDigestA, strings.NewReader("y\n"), &strings.Builder{}, false, false)
	if err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("expected fail-closed with --repo guidance, got %v", err)
	}
}

func TestAssertTrustedSource(t *testing.T) {
	source := "acme/api@r12@" + testDigestA
	for _, tc := range []struct {
		assertion   string
		wantProject bool // project entry recorded
		wantOrg     bool // org entry recorded
	}{
		{"acme", true, true},
		{"acme/api", true, false},
		{source, false, false}, // pin assertion records the pin only
		{"acme/api@" + testDigestA, false, false},
		{"acme/api@r12", false, false},
	} {
		t.Run(tc.assertion, func(t *testing.T) {
			path := gateEnv(t, "")
			if err := assertTrustedSource(tc.assertion, source); err != nil {
				t.Fatal(err)
			}
			policy, err := loadConnectionPolicyFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if !policy.hasPin(source) {
				t.Fatalf("pin always records: %+v", policy)
			}
			if !tc.wantProject && !policy.hasPin(tc.assertion) {
				t.Fatalf("asserted pin must persist independently of the resolved reference: %+v", policy)
			}
			if got := containsEntry(policy.Allow.Projects, "acme/api"); got != tc.wantProject {
				t.Fatalf("project recorded=%v want %v: %+v", got, tc.wantProject, policy)
			}
			if got := containsEntry(policy.Allow.Orgs, "acme"); got != tc.wantOrg {
				t.Fatalf("org recorded=%v want %v: %+v", got, tc.wantOrg, policy)
			}
			// The assertion's granularity must not become the store's
			// configured default level.
			if policy.Record != policyRecordProject {
				t.Fatalf("assertion leaked into default level: %q", policy.Record)
			}
		})
	}
}

func TestAssertTrustedSourceRecordsUnderBroaderGrant(t *testing.T) {
	// An org entry already covers the resolved config, but the typed
	// project-level assertion is an opt-in of its own: it must persist so a
	// later pruning of the org entry does not erase it.
	path := gateEnv(t, `{"allow":{"orgs":["acme"]}}`)
	source := "acme/api@r12@" + testDigestA
	if err := assertTrustedSource("acme/api", source); err != nil {
		t.Fatal(err)
	}
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEntry(policy.Allow.Projects, "acme/api") || !policy.hasPin(source) {
		t.Fatalf("assertion must persist under a broader grant: %+v", policy)
	}
	policy.Allow.Orgs = nil // simulate pruning the broader entry
	if !policy.matches(source) {
		t.Fatal("asserted trust must survive pruning the org entry")
	}
}

func TestAssertTrustedSourceMismatchFails(t *testing.T) {
	path := gateEnv(t, "")
	for _, assertion := range []string{"widgets", "acme/other", "acme/api@r13@" + testDigestB, "acmecorp", "acme/api@" + testDigestB, "acme/api@r13@" + testDigestA} {
		if err := assertTrustedSource(assertion, "acme/api@r12@"+testDigestA); err == nil {
			t.Errorf("assertion %q must not match", assertion)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed assertions must not write the store")
	}
}

func TestGatePromptYes(t *testing.T) {
	path := gateEnv(t, "")
	source := "acme/api@r1@" + testDigestA
	var out strings.Builder
	if err := gateConnectionPolicy(source, strings.NewReader("y\n"), &out, true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), source) || !strings.Contains(out.String(), "[y/N]") {
		t.Fatalf("prompt must show the reference: %q", out.String())
	}
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.matches("acme/api@r2@" + testDigestB) {
		t.Fatalf("yes should record the project: %+v", policy)
	}
}

func TestGatePromptNoRefusesAndRecordsNothing(t *testing.T) {
	path := gateEnv(t, "")
	for _, answer := range []string{"n\n", "\n", "nope\n", ""} {
		err := gateConnectionPolicy("acme/api@r1@"+testDigestA, strings.NewReader(answer), &strings.Builder{}, true, false)
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("answer %q: expected refusal, got %v", answer, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused prompts must not write the store")
	}
}

func TestInvalidStoreBlocksConnections(t *testing.T) {
	content := `{"mode":"frozen","allow":{"projects":["acme/api"],"pins":["invalid"]}}`
	path := gateEnv(t, content)
	source := "acme/api@r1@" + testDigestA
	for _, interactive := range []bool{false, true} {
		var out strings.Builder
		input := strings.NewReader("y\n")
		err := gateConnectionPolicy(source, input, &out, interactive, false)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("expected store error, got %v", err)
		}
		if out.Len() != 0 || input.Len() != len("y\n") {
			t.Fatalf("invalid store must not prompt: %q", out.String())
		}
	}
	if err := assertTrustedSource("acme/api", source); err == nil {
		t.Fatal("explicit assertions must also report the invalid store")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("broken store must never be overwritten:\n%s", data)
	}
}

func TestGateSubstitutionScenario(t *testing.T) {
	// The adversarial case from the review: the caller trusted config A's
	// project; the controlplane answers with a validly endorsed config B from
	// another project. Must never pass silently.
	gateEnv(t, `{"allow":{"projects":["acme/api"]}}`)
	err := gateConnectionPolicy("acme/evil@r1@"+testDigestB, strings.NewReader(""), &strings.Builder{}, false, false)
	if err == nil {
		t.Fatal("substituted config must not pass silently")
	}
}

func TestSeedTrustFromCreate(t *testing.T) {
	path := gateEnv(t, "")
	seedTrustFromCreate("acme/api", "v1.2.3")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	// Default level project, inclusive going down: project + revision pin.
	if !policy.matches("acme/api@v9@"+testDigestB) || !policy.hasPin("acme/api@v1.2.3") {
		t.Fatalf("seed incomplete: %+v", policy)
	}

	// Creating again inside existing trust journals quietly, no duplicates.
	seedTrustFromCreate("acme/api", "v1.2.4")
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Allow.Projects) != 1 || !reloaded.hasPin("acme/api@v1.2.4") {
		t.Fatalf("re-seed wrong: %+v", reloaded)
	}
}

func TestSeedTrustFromCreateDigestRevision(t *testing.T) {
	path := gateEnv(t, "")
	seedTrustFromCreate("acme/api", testDigestA)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	// Project trust and the requested digest are both recorded.
	if !policy.matches("acme/api@r1@"+testDigestB) || !policy.hasPin("acme/api@"+testDigestA) {
		t.Fatalf("digest seed wrong: %+v", policy)
	}
}

func TestGateHashPinAcrossRevisions(t *testing.T) {
	path := gateEnv(t, `{"record":"pin"}`)
	pin := "acme/api@" + testDigestA
	if err := gateConnectionPolicy(pin, strings.NewReader("y\n"), &strings.Builder{}, true, false); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{pin, "acme/api@r1@" + testDigestA, "acme/api@r2@" + testDigestA} {
		if err := gateConnectionPolicy(source, strings.NewReader(""), &strings.Builder{}, false, false); err != nil {
			t.Fatalf("same hash must need no new approval: %v", err)
		}
	}
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.hasPin(pin) || len(policy.Allow.Orgs)+len(policy.Allow.Projects) != 0 {
		t.Fatalf("hash approval must not grant project trust: %+v", policy)
	}
	if err := gateConnectionPolicy("acme/api@r2@"+testDigestB, strings.NewReader(""), &strings.Builder{}, false, false); err == nil {
		t.Fatal("another hash must need approval")
	}
}

func TestGateBareRepoMatchedSkipsJournal(t *testing.T) {
	path := gateEnv(t, `{"allow":{"projects":["ghorg/gh-repo"]}}`)
	var out strings.Builder
	if err := gateConnectionPolicy("ghorg/gh-repo", strings.NewReader(""), &out, false, false); err != nil {
		t.Fatal(err)
	}
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Allow.Pins) != 0 {
		t.Fatalf("bare repo has nothing to pin: %v", policy.Allow.Pins)
	}
	if strings.Contains(out.String(), "journaled") {
		t.Fatalf("no journal announcement expected: %q", out.String())
	}
}
