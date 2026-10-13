package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testDigestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-configs.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConnectionPolicyMissingFileIsEmptyStore(t *testing.T) {
	policy, err := loadConnectionPolicyFrom(filepath.Join(t.TempDir(), "known-configs.yml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if policy.Mode != policyModePrompt || policy.Record != policyRecordProject {
		t.Fatalf("defaults wrong: mode=%q level=%q", policy.Mode, policy.Record)
	}
	if len(policy.Orgs)+len(policy.Projects)+len(policy.Pins) != 0 {
		t.Fatalf("expected empty store: %+v", policy)
	}
}

func TestLoadConnectionPolicyFull(t *testing.T) {
	path := writePolicyFile(t, `mode: frozen
record: pin
allow:
  orgs:
    - acme            # whole org
  projects:
    - acme/api
  pins:
    - acme/batch@r12@`+testDigestA+`
`)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != policyModeFrozen || policy.Record != policyRecordPin {
		t.Fatalf("mode=%q level=%q", policy.Mode, policy.Record)
	}
	if len(policy.Orgs) != 1 || policy.Orgs[0] != "acme" ||
		len(policy.Projects) != 1 || policy.Projects[0] != "acme/api" ||
		len(policy.Pins) != 1 || policy.Pins[0] != "acme/batch@r12@"+testDigestA {
		t.Fatalf("buckets wrong: %+v", policy)
	}
}

func TestLoadConnectionPolicyDefaultsWhenFieldsAbsent(t *testing.T) {
	path := writePolicyFile(t, "allow:\n  projects:\n    - acme/api\n")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != policyModePrompt || policy.Record != policyRecordProject {
		t.Fatalf("mode=%q level=%q", policy.Mode, policy.Record)
	}
}

func TestLoadConnectionPolicyMalformedFallsBackToSafeDefaults(t *testing.T) {
	for name, content := range map[string]string{
		"bad yaml":          "mode: [unclosed\n",
		"unknown mode":      "mode: open\n",
		"unknown level":     "record: everything\n",
		"wrong shape":       "allow: [a, b]\n",
		"project under org": "allow:\n  orgs:\n    - acme/api\n",
		"pin under project": "allow:\n  projects:\n    - acme/api@r1@" + testDigestA + "\n",
		"org under pin":     "allow:\n  pins:\n    - acme\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t, content)
			policy, err := loadConnectionPolicyFrom(path)
			if err == nil {
				t.Fatal("expected error")
			}
			// The fallback must land on prompt with nothing allowed —
			// never on accepting anything.
			if policy.Mode != policyModePrompt || len(policy.Orgs)+len(policy.Projects)+len(policy.Pins) != 0 {
				t.Fatalf("unsafe fallback: %+v", policy)
			}
		})
	}
}

func TestLoadConnectionPolicyEmptyFile(t *testing.T) {
	path := writePolicyFile(t, "")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != policyModePrompt || len(policy.Orgs)+len(policy.Projects)+len(policy.Pins) != 0 {
		t.Fatalf("%+v", policy)
	}
}

func TestLoadConnectionPolicyNullDocument(t *testing.T) {
	path := writePolicyFile(t, "null\n")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Orgs)+len(policy.Projects)+len(policy.Pins) != 0 {
		t.Fatalf("null document should be an empty store: %+v", policy)
	}
	// Recording must work: the scalar root is discarded and a fresh mapping
	// tree is built in memory.
	if _, err := policy.recordPin("acme/api@r1@" + testDigestA); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.hasPin("acme/api@r1@" + testDigestA) {
		t.Fatalf("pin not recorded over null document: %+v", reloaded)
	}
}

func TestMatches(t *testing.T) {
	policy := connectionPolicy{
		Orgs:     []string{"acme"},
		Projects: []string{"widgets/api"},
		Pins: []string{
			"widgets/batch@r12@" + testDigestA,
			"ghorg/gh-repo@v1.2.3",
		},
	}
	for _, tc := range []struct {
		source string
		want   bool
	}{
		// org entry covers everything in the org
		{"acme/anything@r9@" + testDigestB, true},
		{"acme/api@r1@" + testDigestA, true},
		// project entry covers any revision
		{"widgets/api@r1@" + testDigestA, true},
		{"widgets/api@r2@" + testDigestB, true},
		// pin covers only itself
		{"widgets/batch@r12@" + testDigestA, true},
		{"widgets/batch@r13@" + testDigestB, false},
		{"widgets/batch@r12@" + testDigestB, false},
		// pin without digest covers any digest of that revision
		{"ghorg/gh-repo@v1.2.3@" + testDigestA, true},
		{"ghorg/gh-repo@v1.2.3", true},
		{"ghorg/gh-repo@v1.2.4", false},
		// no partial-label matches
		{"acmecorp/api@r1@" + testDigestA, false},
		{"widgets/api2@r1@" + testDigestA, false},
		// unknown org/project
		{"evil/api@r1@" + testDigestA, false},
		{"", false},
	} {
		if got := policy.matches(tc.source); got != tc.want {
			t.Errorf("matches(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

func TestMatchesEmptyStoreMatchesNothing(t *testing.T) {
	policy := connectionPolicy{}
	if policy.matches("acme/api@r1@" + testDigestA) {
		t.Fatal("empty store must not match")
	}
}

func TestEntryForLevel(t *testing.T) {
	source := "acme/api@r12@" + testDigestA
	for _, tc := range []struct {
		level, want string
	}{
		{policyRecordOrg, "acme"},
		{policyRecordProject, "acme/api"},
		{policyRecordPin, source},
	} {
		got, err := entryForLevel(source, tc.level)
		if err != nil {
			t.Fatalf("level %s: %v", tc.level, err)
		}
		if got != tc.want {
			t.Errorf("level %s: got %q want %q", tc.level, got, tc.want)
		}
	}
}

func TestEntryForLevelRejectsGarbage(t *testing.T) {
	for _, source := range []string{"", "no-slash", "a/b@tag@sha256:short", "a/b c"} {
		if _, err := entryForLevel(source, policyRecordProject); err == nil {
			t.Errorf("expected error for %q", source)
		}
	}
	if _, err := entryForLevel("acme/api@r1@"+testDigestA, "bogus"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestRecordTrustWritesAtConfiguredLevel(t *testing.T) {
	source := "acme/api@r12@" + testDigestA
	for level, wantMatch := range map[string]string{
		policyRecordOrg:     "acme/other@r1@" + testDigestB,
		policyRecordProject: "acme/api@r99@" + testDigestB,
		policyRecordPin:     source,
	} {
		t.Run(level, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known-configs.yml")
			policy, err := loadConnectionPolicyFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			policy.Record = level
			if err := policy.recordTrust(source); err != nil {
				t.Fatal(err)
			}
			reloaded, err := loadConnectionPolicyFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reloaded.matches(wantMatch) {
				t.Fatalf("level %s should cover %q: %+v", level, wantMatch, reloaded)
			}
			// And nothing broader than the recorded level may pass.
			if level != policyRecordOrg && reloaded.matches("acme/other@r1@"+testDigestB) {
				t.Fatalf("level %s must not cover sibling projects: %+v", level, reloaded)
			}
			if level == policyRecordPin && reloaded.matches("acme/api@r12@"+testDigestB) {
				t.Fatalf("pin must not cover the same revision with another digest: %+v", reloaded)
			}
		})
	}
}

func TestRecordTrustIsInclusiveGoingDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.yml")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	policy.Record = policyRecordOrg
	source := "acme/api@r12@" + testDigestA
	if err := policy.recordTrust(source); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEntry(reloaded.Orgs, "acme") ||
		!containsEntry(reloaded.Projects, "acme/api") ||
		!reloaded.hasPin(source) {
		t.Fatalf("org-yes should record all narrower levels: %+v", reloaded)
	}

	// Tightening: delete the broad lines; the narrower buckets carry you.
	reloaded.Orgs, reloaded.Projects = nil, nil
	if !reloaded.matches(source) {
		t.Fatal("pin should carry trust after tightening")
	}
	if reloaded.matches("acme/api@r99@" + testDigestB) {
		t.Fatal("tightened store must not cover unseen revisions")
	}
}

func TestRecordTrustDedupes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.yml")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	policy.Record = policyRecordOrg
	for _, source := range []string{
		"acme/api@r12@" + testDigestA,
		"acme/api@r12@" + testDigestA, // same again
		"acme/api@r13@" + testDigestB, // same org+project, new pin
	} {
		if err := policy.recordTrust(source); err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Orgs) != 1 || len(reloaded.Projects) != 1 || len(reloaded.Pins) != 2 {
		t.Fatalf("dedupe wrong: orgs=%v projects=%v pins=%v", reloaded.Orgs, reloaded.Projects, reloaded.Pins)
	}
}

func TestRecordPinJournalsAndDedupes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.yml")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	source := "acme/api@r12@" + testDigestA
	fresh, err := policy.recordPin(source)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Fatal("first record should report new")
	}
	again, err := policy.recordPin(source)
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Fatal("duplicate record should not report new")
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Pins) != 1 {
		t.Fatalf("expected one journaled pin: %v", reloaded.Pins)
	}
	// Journaling a pin must not widen policy.
	if reloaded.matches("acme/api@r13@" + testDigestB) {
		t.Fatal("journal pin must not cover other revisions")
	}
}

func TestRecordPinSortsIntoProjectGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.yml")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{
		"widgets/batch@r2@" + testDigestB,
		"acme/api@r1@" + testDigestA,
		"widgets/batch@r1@" + testDigestA,
	} {
		if _, err := policy.recordPin(pin); err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"acme/api@r1@" + testDigestA,
		"widgets/batch@r1@" + testDigestA,
		"widgets/batch@r2@" + testDigestB,
	}
	for i := range want {
		if reloaded.Pins[i] != want[i] {
			t.Fatalf("pins not grouped: %v", reloaded.Pins)
		}
	}
}

func TestRecordPinRejectsUnpinned(t *testing.T) {
	policy := connectionPolicy{path: filepath.Join(t.TempDir(), "known-configs.yml")}
	if _, err := policy.recordPin("acme/api"); err == nil {
		t.Fatal("expected error for unpinned reference")
	}
}

func TestWritesPreserveComments(t *testing.T) {
	path := writePolicyFile(t, `# trust store — hands off, humans only
mode: prompt
record: project
allow:
  projects:
    - acme/api   # prod api, any revision is fine
`)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.recordPin("acme/api@r12@" + testDigestA); err != nil {
		t.Fatal(err)
	}
	if err := policy.recordTrust("widgets/api@r1@" + testDigestB); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"# trust store — hands off, humans only",
		"# prod api, any revision is fine",
		"acme/api@r12@" + testDigestA,
		"widgets/api",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("file lost %q:\n%s", want, text)
		}
	}
}

func TestAppendIntoEmptyBuckets(t *testing.T) {
	for name, content := range map[string]string{
		"bare allow": "mode: prompt\nallow:\n",
		"empty pins": "allow:\n  pins:\n",
		"no allow":   "mode: prompt\n",
		"empty file": "",
		"other keys": "allow:\n  orgs:\n    - acme\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t, content)
			policy, err := loadConnectionPolicyFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy.recordPin("acme/api@r1@" + testDigestA); err != nil {
				t.Fatal(err)
			}
			reloaded, err := loadConnectionPolicyFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reloaded.hasPin("acme/api@r1@" + testDigestA) {
				t.Fatalf("pin not journaled: %+v", reloaded)
			}
		})
	}
}

func TestAppendCreatesFileWithDefaultsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "known-configs.yml")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.recordTrust("acme/api@r1@" + testDigestA); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Mode != policyModePrompt || reloaded.Record != policyRecordProject {
		t.Fatalf("fresh file should make defaults explicit: %+v", reloaded)
	}
	if !reloaded.matches("acme/api@r2@" + testDigestB) {
		t.Fatalf("project trust not recorded: %+v", reloaded)
	}
}

func TestPruneBroaderThan(t *testing.T) {
	content := `# header comment survives
mode: prompt
record: pin
allow:
  orgs:
    - acme
  projects:
    - acme/api
  pins:
    - acme/api@r1@` + testDigestA + ` # pin comment survives
`
	t.Run("pin prunes orgs and projects", func(t *testing.T) {
		path := writePolicyFile(t, content)
		policy, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.pruneBroaderThan(policyRecordPin); err != nil {
			t.Fatal(err)
		}
		reloaded, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(reloaded.Orgs)+len(reloaded.Projects) != 0 || len(reloaded.Pins) != 1 {
			t.Fatalf("prune wrong: %+v", reloaded)
		}
		data, _ := os.ReadFile(path)
		for _, want := range []string{"# header comment survives", "# pin comment survives"} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("lost %q:\n%s", want, data)
			}
		}
		if reloaded.matches("acme/other@r1@" + testDigestB) {
			t.Fatal("org grant must be gone")
		}
		if !reloaded.matches("acme/api@r1@" + testDigestA) {
			t.Fatal("pin must survive")
		}
	})
	t.Run("project prunes orgs only", func(t *testing.T) {
		path := writePolicyFile(t, content)
		policy, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.pruneBroaderThan(policyRecordProject); err != nil {
			t.Fatal(err)
		}
		reloaded, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(reloaded.Orgs) != 0 || len(reloaded.Projects) != 1 {
			t.Fatalf("prune wrong: %+v", reloaded)
		}
	})
	t.Run("org level prunes nothing", func(t *testing.T) {
		path := writePolicyFile(t, content)
		policy, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.pruneBroaderThan(policyRecordOrg); err != nil {
			t.Fatal(err)
		}
		reloaded, err := loadConnectionPolicyFrom(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(reloaded.Orgs) != 1 || len(reloaded.Projects) != 1 {
			t.Fatalf("org level must prune nothing: %+v", reloaded)
		}
	})
}

func TestConnectionPolicyPathEnvOverride(t *testing.T) {
	t.Setenv(envKnownConfigs, "/tmp/elsewhere.yml")
	path, err := connectionPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tmp/elsewhere.yml" {
		t.Fatalf("got %q", path)
	}
}
