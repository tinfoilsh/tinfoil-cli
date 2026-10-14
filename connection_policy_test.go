package main

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

const (
	testDigestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-configs.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConnectionPolicyMissingFileIsEmptyStore(t *testing.T) {
	policy, err := loadConnectionPolicyFrom(filepath.Join(t.TempDir(), "known-configs.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if policy.Mode != policyModePrompt || policy.Record != policyRecordProject {
		t.Fatalf("defaults wrong: mode=%q level=%q", policy.Mode, policy.Record)
	}
	if len(policy.Allow.Orgs)+len(policy.Allow.Projects)+len(policy.Allow.Pins) != 0 {
		t.Fatalf("expected empty store: %+v", policy)
	}
}

func TestLoadConnectionPolicyFull(t *testing.T) {
	path := writePolicyFile(t, `{
  "mode": "frozen",
  "record": "pin",
  "allow": {
    "orgs": ["acme"],
    "projects": ["acme/api"],
    "pins": ["acme/batch@r12@`+testDigestA+`"]
  }
}`)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != policyModeFrozen || policy.Record != policyRecordPin {
		t.Fatalf("mode=%q level=%q", policy.Mode, policy.Record)
	}
	if len(policy.Allow.Orgs) != 1 || policy.Allow.Orgs[0] != "acme" ||
		len(policy.Allow.Projects) != 1 || policy.Allow.Projects[0] != "acme/api" ||
		len(policy.Allow.Pins) != 1 || policy.Allow.Pins[0] != "acme/batch@r12@"+testDigestA {
		t.Fatalf("buckets wrong: %+v", policy)
	}
}

func TestLoadConnectionPolicyDefaultsWhenFieldsAbsent(t *testing.T) {
	path := writePolicyFile(t, `{"allow":{"projects":["acme/api"]}}`)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != policyModePrompt || policy.Record != policyRecordProject {
		t.Fatalf("mode=%q level=%q", policy.Mode, policy.Record)
	}
}

func TestLoadConnectionPolicyRejectsInvalidStore(t *testing.T) {
	for name, content := range map[string]string{
		"bad JSON":          `{"mode":`,
		"unknown mode":      `{"mode":"open"}`,
		"unknown level":     `{"record":"everything"}`,
		"unknown field":     `{"mod":"frozen"}`,
		"unknown bucket":    `{"allow":{"project":["acme/api"]}}`,
		"duplicate field":   `{"mode":"frozen","mode":"prompt"}`,
		"wrong shape":       `{"allow":["a","b"]}`,
		"project under org": `{"allow":{"orgs":["acme/api"]}}`,
		"pin under project": `{"allow":{"projects":["acme/api@r1@` + testDigestA + `"]}}`,
		"org under pin":     `{"allow":{"pins":["acme"]}}`,
		"empty entry":       `{"allow":{"orgs":[" "]}}`,
		"null entry":        `{"allow":{"orgs":[null]}}`,
		"empty file":        "",
		"null document":     "null",
		"array document":    "[]",
		"extra document":    `{} {}`,
		"null mode":         `{"mode":null}`,
		"empty mode":        `{"mode":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t, content)
			if _, err := loadConnectionPolicyFrom(path); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMatches(t *testing.T) {
	policy := connectionPolicy{}
	policy.Allow.Orgs = []string{"acme"}
	policy.Allow.Projects = []string{"widgets/api"}
	policy.Allow.Pins = []string{
		"widgets/batch@r12@" + testDigestA,
		"ghorg/gh-repo@v1.2.3",
		"widgets/hash-pinned@" + testDigestA,
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
		{"widgets/batch@r13@" + testDigestA, false},
		{"widgets/batch@" + testDigestA, false},
		{"widgets/batch@r12", false},
		// A digest-only pin allows any revision with that project's exact bytes.
		{"widgets/hash-pinned@" + testDigestA, true},
		{"widgets/hash-pinned@r1@" + testDigestA, true},
		{"widgets/hash-pinned@r2@" + testDigestA, true},
		{"widgets/hash-pinned@r1@" + testDigestB, false},
		{"widgets/hash-pinned@r1", false},
		{"other/hash-pinned@r1@" + testDigestA, false},
		// pin without digest covers any digest of that revision
		{"ghorg/gh-repo@v1.2.3@" + testDigestA, true},
		{"ghorg/gh-repo@v1.2.3", true},
		{"ghorg/gh-repo@v1.2.4", false},
		// no partial-label matches
		{"acmecorp/api@r1@" + testDigestA, false},
		{"widgets/api2@r1@" + testDigestA, false},
		{"widgets/api/nested@r1@" + testDigestA, false},
		{"acme/api@r1@sha256:short", false},
		{"ghorg/gh-repo@v1.2.3/nested", false},
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
			path := filepath.Join(t.TempDir(), "known-configs.json")
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
	path := filepath.Join(t.TempDir(), "known-configs.json")
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
	if !containsEntry(reloaded.Allow.Orgs, "acme") ||
		!containsEntry(reloaded.Allow.Projects, "acme/api") ||
		!reloaded.hasPin(source) {
		t.Fatalf("org-yes should record all narrower levels: %+v", reloaded)
	}

	// Tightening: delete the broad lines; the narrower buckets carry you.
	reloaded.Allow.Orgs, reloaded.Allow.Projects = nil, nil
	if !reloaded.matches(source) {
		t.Fatal("pin should carry trust after tightening")
	}
	if reloaded.matches("acme/api@r99@" + testDigestB) {
		t.Fatal("tightened store must not cover unseen revisions")
	}
}

func TestRecordTrustDedupes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.json")
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
	if len(reloaded.Allow.Orgs) != 1 || len(reloaded.Allow.Projects) != 1 || len(reloaded.Allow.Pins) != 2 {
		t.Fatalf("dedupe wrong: orgs=%v projects=%v pins=%v", reloaded.Allow.Orgs, reloaded.Allow.Projects, reloaded.Allow.Pins)
	}
}

func TestRecordPinJournalsAndDedupes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.json")
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
	if len(reloaded.Allow.Pins) != 1 {
		t.Fatalf("expected one journaled pin: %v", reloaded.Allow.Pins)
	}
	// Journaling a pin must not widen policy.
	if reloaded.matches("acme/api@r13@" + testDigestB) {
		t.Fatal("journal pin must not cover other revisions")
	}
}

func TestRecordPinSortsIntoProjectGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-configs.json")
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
		if reloaded.Allow.Pins[i] != want[i] {
			t.Fatalf("pins not grouped: %v", reloaded.Allow.Pins)
		}
	}
}

func TestRecordPinRejectsUnpinned(t *testing.T) {
	policy := connectionPolicy{path: filepath.Join(t.TempDir(), "known-configs.json")}
	if _, err := policy.recordPin("acme/api"); err == nil {
		t.Fatal("expected error for unpinned reference")
	}
}

func TestSetDefaultsPreservesAllowList(t *testing.T) {
	path := writePolicyFile(t, `{"allow":{"projects":["acme/api"]}}`)
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.recordPin("widgets/batch@r12@" + testDigestA); err != nil {
		t.Fatal(err)
	}
	if err := policy.setDefaults(policyModeFrozen, policyRecordPin); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Mode != policyModeFrozen || reloaded.Record != policyRecordPin ||
		!reloaded.matches("acme/api@r99@"+testDigestB) || !reloaded.hasPin("widgets/batch@r12@"+testDigestA) {
		t.Fatalf("defaults or allow list lost: %+v", reloaded)
	}
}

func TestAppendIntoEmptyBuckets(t *testing.T) {
	for name, content := range map[string]string{
		"empty allow":  `{"mode":"prompt","allow":{}}`,
		"empty pins":   `{"allow":{"pins":[]}}`,
		"no allow":     `{"mode":"prompt"}`,
		"empty object": `{}`,
		"other keys":   `{"allow":{"orgs":["acme"]}}`,
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
	path := filepath.Join(t.TempDir(), "sub", "known-configs.json")
	policy, err := loadConnectionPolicyFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.recordTrust("acme/api@r1@" + testDigestA); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["mode"] != policyModePrompt || stored["record"] != policyRecordProject {
		t.Fatalf("missing explicit defaults: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store permissions = %o, want 600", info.Mode().Perm())
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
	content := `{"mode":"prompt","record":"pin","allow":{
  "orgs":["acme"],"projects":["acme/api"],"pins":["acme/api@r1@` + testDigestA + `"]}}`
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
		if len(reloaded.Allow.Orgs)+len(reloaded.Allow.Projects) != 0 || len(reloaded.Allow.Pins) != 1 {
			t.Fatalf("prune wrong: %+v", reloaded)
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
		if len(reloaded.Allow.Orgs) != 0 || len(reloaded.Allow.Projects) != 1 {
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
		if len(reloaded.Allow.Orgs) != 1 || len(reloaded.Allow.Projects) != 1 {
			t.Fatalf("org level must prune nothing: %+v", reloaded)
		}
	})
}

func TestConnectionPolicyPathEnvOverride(t *testing.T) {
	t.Setenv(envKnownConfigs, "/tmp/elsewhere.json")
	path, err := connectionPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tmp/elsewhere.json" {
		t.Fatalf("got %q", path)
	}
}

func TestConnectionPolicyDoesNotIgnoreYAMLStore(t *testing.T) {
	t.Setenv(envKnownConfigs, "")
	policyHome := t.TempDir()
	t.Setenv("HOME", policyHome)
	t.Setenv("USERPROFILE", policyHome)
	path, err := connectionPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(filepath.Dir(path), legacyConnectionPolicyFileName)
	if err := os.WriteFile(legacy, []byte("mode: frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConnectionPolicy(); err == nil {
		t.Fatal("YAML store must not be silently replaced by an empty JSON store")
	}
	if err := os.WriteFile(path, []byte(`{"mode":"frozen"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := loadConnectionPolicy()
	if err != nil || policy.Mode != policyModeFrozen {
		t.Fatalf("converted store: mode=%q, err=%v", policy.Mode, err)
	}
}
