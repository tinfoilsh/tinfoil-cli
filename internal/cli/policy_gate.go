package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/trust"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/term"
)

// The trust gate runs where a connection's expected config was resolved from
// the controlplane rather than supplied by the caller (an explicit --repo or
// --project skips it: that IS the caller's expectation). It checks the resolved
// reference against the known-configs store, so a substituted config prompts
// or fails closed instead of verifying silently, and journals the exact pin
// of every config actually connected to.
// Every connection trust decision goes through this file: the gate for
// controlplane-resolved configs, --repo and --project assertions, and
// create-time seeding.
// GitHub repositories and registry projects are separate namespaces: a
// resolved config is only ever checked against entries and assertions in its
// own.

// overridePin returns the pin the verifier enforces for a resolved config:
// the caller's assertion in the resolved config's namespace when there is
// one. A bare org is a valid assertion but not a verifier pin: tinfoil-go's
// reference grammar requires owner/name. assertTrustedSource checks the org
// against the resolved name, and the verifier pins the resolved reference.
func overridePin(asserted, resolved verify.Pin) (verify.Pin, error) {
	if asserted == (verify.Pin{}) {
		return resolved, nil
	}
	override := verify.Pin{Project: asserted.Project}
	if resolved.Repo != "" {
		override = verify.Pin{Repo: asserted.Repo}
	}
	if override == (verify.Pin{}) {
		return override, fmt.Errorf("%s is a %s; state it with %s instead of %s", pinText(resolved), namespaceName(resolved), trust.Flag(resolved), trust.Flag(asserted))
	}
	if !strings.Contains(pinText(override), "/") {
		return resolved, nil
	}
	return override, nil
}

func addTrustDangerousFlag(trustOpts *trustOptions, cmd *cobra.Command) {
	cmd.Flags().BoolVar(&trustOpts.trustDangerous, "dangerous", false, "Trust whatever config the controlplane returns, without recording it")
}

func enforceConnectionPolicy(streams commandIO, trustOpts *trustOptions, source verify.Pin) error {
	interactive := term.IsTerminal(int(streamFD(streams.in)))
	return gateConnectionPolicy(source, streams.in, streams.err, interactive, trustOpts.trustDangerous)
}

func trustConnectionSource(streams commandIO, trustOpts *trustOptions, source, assertion verify.Pin) error {
	if assertion != (verify.Pin{}) {
		return assertTrustedSource(streams, assertion, source)
	}
	return enforceConnectionPolicy(streams, trustOpts, source)
}

func gateConnectionPolicy(pin verify.Pin, in io.Reader, out io.Writer, interactive, dangerous bool) error {
	source, err := trust.Reference(pin)
	if err != nil {
		return err
	}
	flag := trust.Flag(pin)
	if dangerous {
		fmt.Fprintf(out, "%s accepting controlplane-chosen config %s without checking known-configs; nothing recorded\n", errText("DANGEROUS:"), source)
		return nil
	}

	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}

	if policy.Matches(pin) {
		if policy.Mode == policyModeFrozen {
			// Frozen means the CLI never writes the file, journal included;
			// a first-seen config is still announced.
			if _, tag, digest, err := verify.ParseReference(source); err == nil && (tag != "" || digest != "") && !policy.HasPin(pin) {
				fmt.Fprintf(out, "New config (not journaled, mode: frozen): %s\n", source)
			}
			return nil
		}
		journalPin(&policy, pin, out)
		return nil
	}

	if policy.Mode == policyModeFrozen {
		return fmt.Errorf("config %s is not allowed by %s (mode: frozen)\nAdd it to the %s section of the file, pass %s %s to pin this invocation, or --dangerous to skip the check", source, policy.Path(), trust.Section(pin), flag, source)
	}

	if !interactive {
		return fmt.Errorf("config %s is not in your known configs (%s)\nPass %s %s (after checking it is what you expect) to assert and record it, or --dangerous to skip the check", source, policy.Path(), flag, source)
	}
	accepted, err := promptTrustConfig(in, out, source+" ("+namespaceName(pin)+")", policy.Record)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("refusing config %s", source)
	}
	if err := policy.RecordTrust(pin); err != nil {
		return fmt.Errorf("recording trust for %s: %w", source, err)
	}
	fmt.Fprintf(out, "Recorded %s as %s in %s\n", source, policy.Record, policy.Path())
	return nil
}

// journalPin records the exact reference of a policy-passing connect and
// announces a first sight. Best-effort: journaling failures warn, they do not
// block a connection that policy already allows. References without a
// revision or digest (a bare owner/repo) have no exact config to journal and are
// skipped.
func journalPin(policy *connectionPolicy, pin verify.Pin, out io.Writer) {
	source := pinText(pin)
	_, tag, digest, err := verify.ParseReference(source)
	if err != nil || (tag == "" && digest == "") {
		return
	}
	fresh, err := policy.RecordPin(pin)
	if err != nil {
		fmt.Fprintf(out, "%s could not journal %s: %v\n", askText("warning:"), source, err)
		return
	}
	if fresh {
		fmt.Fprintf(out, "New config journaled: %s\n", source)
	}
}

// seedTrustFromCreate records the caller's typed intent at container create
// time, so the first connect on this machine needs no prompt. The typed
// --repo or --project is the assertion (project granularity); the revision
// rides along as the pin, including digest-form revisions (sha256:…). The
// config source selects the namespace. Best-effort: the container exists
// either way.
func seedTrustFromCreate(streams commandIO, configSource, repoRef, revision string) {
	assertion := strings.TrimSpace(repoRef)
	if assertion == "" {
		return
	}
	source := assertion
	if rev := strings.TrimSpace(revision); rev != "" {
		source += "@" + rev
	}
	asserted, resolved := verify.Pin{Repo: assertion}, verify.Pin{Repo: source}
	if configSource == containerSourceRegistry {
		asserted, resolved = verify.Pin{Project: assertion}, verify.Pin{Project: source}
	}
	if err := assertTrustedSource(streams, asserted, resolved); err != nil {
		fmt.Fprintf(streams.err, "%s not recording %s: %v\n", askText("warning:"), source, err)
	}
}

// assertTrustedSource enforces and persists an expectation the caller stated
// explicitly (--repo, --project, or the create-time project+revision). The assertion may
// sit at any granularity — org, org/project, or pinned — and the resolved
// source must fall under it. A typed assertion is exactly as deliberate as a
// prompt-yes, so it records the same way (inclusive going down from the
// assertion's granularity) instead of being retyped forever. Recording
// failures warn rather than block: the assertion already protected this
// invocation.
func assertTrustedSource(streams commandIO, assertion, resolved verify.Pin) error {
	recordSource, level, err := trust.AssertionRecord(assertion, resolved)
	if err != nil {
		return err
	}
	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}
	// Record the assertion even when an existing (possibly broader) grant
	// already matches: the typed granularity is an opt-in of its own, and it
	// must survive a later pruning of the broader entries. Deduplication
	// makes this a no-op when everything is already present.
	changed, err := policy.RecordTrustAt(recordSource, level)
	if err != nil {
		fmt.Fprintf(streams.err, "%s could not record %s in known-configs: %v\n", askText("warning:"), pinText(resolved), err)
		return nil
	}
	if changed {
		fmt.Fprintf(streams.err, "Recorded %s as %s in %s\n", pinText(recordSource), level, policy.Path())
	}
	if recordSource != resolved {
		journalPin(&policy, resolved, streams.err)
	}
	return nil
}

func promptTrustConfig(in io.Reader, out io.Writer, source, level string) (bool, error) {
	fmt.Fprintf(out, `This connection resolves to config:

  %s

It is not in your known configs. The reference comes from Tinfoil;
cross-check it against your own build or deploy records if unsure.
%s `, valueText(source), askText(fmt.Sprintf("Trust it and record as %q? [y/N]", level)))
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

func namespaceName(pin verify.Pin) string {
	if pin.Repo != "" {
		return "GitHub repository"
	}
	return "registry project"
}
