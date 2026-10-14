package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/term"
)

// The trust gate runs where a connection's expected config was resolved from
// the controlplane rather than supplied by the caller (an explicit --repo
// skips it: that IS the caller's expectation). It checks the resolved
// reference against the known-configs store, so a substituted config prompts
// or fails closed instead of verifying silently, and journals the exact pin
// of every config actually connected to.
// Every connection trust decision goes through this file: the gate for
// controlplane-resolved configs, --repo assertions, and create-time seeding.
var trustDangerous bool

func addTrustDangerousFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&trustDangerous, "dangerous", false, "Skip the known-configs check and accept whatever config the controlplane returns; records nothing")
}

func enforceConnectionPolicy(source string) error {
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	return gateConnectionPolicy(source, os.Stdin, os.Stderr, interactive, trustDangerous)
}

func gateConnectionPolicy(source string, in io.Reader, out io.Writer, interactive, dangerous bool) error {
	source = strings.TrimSpace(source)
	if dangerous {
		fmt.Fprintf(out, "DANGEROUS: accepting controlplane-chosen config %s without checking known-configs; nothing recorded\n", source)
		return nil
	}

	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}

	if policy.matches(source) {
		if policy.Mode == policyModeFrozen {
			// Frozen means the CLI never writes the file, journal included;
			// a first-seen config is still announced.
			if _, tag, digest, err := verify.ParseReference(source); err == nil && (tag != "" || digest != "") && !policy.hasPin(source) {
				fmt.Fprintf(out, "New config (not journaled, mode: frozen): %s\n", source)
			}
			return nil
		}
		journalPin(&policy, source, out)
		return nil
	}

	if policy.Mode == policyModeFrozen {
		return fmt.Errorf("config %s is not allowed by %s (mode: frozen)\nAdd it to the file, pass --repo %s to pin this invocation, or --dangerous to skip the check", source, policy.path, source)
	}

	if !interactive {
		return fmt.Errorf("config %s is not in your known configs (%s)\nPass --repo %s (after checking it is what you expect) to assert and record it, or --dangerous to skip the check", source, policy.path, source)
	}
	accepted, err := promptTrustConfig(in, out, source, policy.Record)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("refusing config %s", source)
	}
	if err := policy.recordTrust(source); err != nil {
		return fmt.Errorf("recording trust for %s: %w", source, err)
	}
	fmt.Fprintf(out, "Recorded %s as %s in %s\n", source, policy.Record, policy.path)
	return nil
}

// journalPin records the exact reference of a policy-passing connect and
// announces a first sight. Best-effort: journaling failures warn, they do not
// block a connection that policy already allows. References without a
// revision or digest (a bare owner/repo) have no exact config to journal and are
// skipped.
func journalPin(policy *connectionPolicy, source string, out io.Writer) {
	_, tag, digest, err := verify.ParseReference(source)
	if err != nil || (tag == "" && digest == "") {
		return
	}
	fresh, err := policy.recordPin(source)
	if err != nil {
		fmt.Fprintf(out, "warning: could not journal %s: %v\n", source, err)
		return
	}
	if fresh {
		fmt.Fprintf(out, "New config journaled: %s\n", source)
	}
}

// seedTrustFromCreate records the caller's typed intent at container create
// time, so the first connect on this machine needs no prompt. The typed
// --repo is the assertion (project granularity); the revision rides along as
// the pin, including digest-form revisions (sha256:…). Best-effort: the
// container exists either way.
func seedTrustFromCreate(repoRef, revision string) {
	assertion := strings.TrimSpace(repoRef)
	if assertion == "" {
		return
	}
	source := assertion
	if rev := strings.TrimSpace(revision); rev != "" {
		source += "@" + rev
	}
	if err := assertTrustedSource(assertion, source); err != nil {
		fmt.Fprintf(os.Stderr, "warning: not recording %s: %v\n", source, err)
	}
}

// assertTrustedSource enforces and persists an expectation the caller stated
// explicitly (--repo, or the create-time project+revision). The assertion may
// sit at any granularity — org, org/project, or pinned — and the resolved
// source must fall under it. A typed assertion is exactly as deliberate as a
// prompt-yes, so it records the same way (inclusive going down from the
// assertion's granularity) instead of being retyped forever. Recording
// failures warn rather than block: the assertion already protected this
// invocation.
func assertTrustedSource(assertion, resolvedSource string) error {
	assertion = strings.TrimSpace(assertion)
	resolvedSource = strings.TrimSpace(resolvedSource)
	if assertion == "" || resolvedSource == "" {
		return fmt.Errorf("empty reference")
	}
	if !referenceMatches(assertion, resolvedSource) {
		return fmt.Errorf("resolved config %s does not match --repo %s", resolvedSource, assertion)
	}
	level, err := referenceGranularity(assertion)
	if err != nil {
		return fmt.Errorf("--repo: %w", err)
	}
	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}
	// Record the assertion even when an existing (possibly broader) grant
	// already matches: the typed granularity is an opt-in of its own, and it
	// must survive a later pruning of the broader entries. Deduplication
	// makes this a no-op when everything is already present.
	recordSource := resolvedSource
	if level == policyRecordPin {
		recordSource = assertion
	}
	changed, err := policy.recordTrustAt(recordSource, level)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record %s in known-configs: %v\n", resolvedSource, err)
		return nil
	}
	if changed {
		fmt.Fprintf(os.Stderr, "Recorded %s as %s in %s\n", recordSource, level, policy.path)
	}
	if recordSource != resolvedSource {
		journalPin(&policy, resolvedSource, os.Stderr)
	}
	return nil
}

// referenceGranularity classifies a caller-stated reference: a bare name is
// an org, owner/name is a project, anything pinned is a pin.
func referenceGranularity(ref string) (string, error) {
	if !strings.Contains(ref, "/") {
		if err := validateEntry(ref, policyRecordOrg); err != nil {
			return "", err
		}
		return policyRecordOrg, nil
	}
	_, tag, digest, err := verify.ParseReference(ref)
	if err != nil {
		return "", err
	}
	if tag == "" && digest == "" {
		return policyRecordProject, nil
	}
	return policyRecordPin, nil
}

func promptTrustConfig(in io.Reader, out io.Writer, source, level string) (bool, error) {
	fmt.Fprintf(out, `This connection resolves to config:

  %s

It is not in your known configs. The reference comes from Tinfoil;
cross-check it against your own build or deploy records if unsure.
Trust it and record as %q? [y/N] `, source, level)
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		fmt.Fprintln(out)
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
