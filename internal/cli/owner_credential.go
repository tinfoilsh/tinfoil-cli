package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-cli/internal/owner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type noLocalKeys = owner.NoLocalKeys

func removeExportedKeys() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	return owner.RemoveExportedKeys(path, os.Getenv("SSH_AUTH_SOCK"))
}

func ownerService(streams commandIO, identityOpts *identityOptions, cp *cpClient) (*owner.Service, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	credentials, err := cp.auth()
	if err != nil {
		return nil, err
	}
	s := &owner.Service{ConfigPath: path, Home: os.UserHomeDir, IdentityFile: identityOpts.attestSSHIdentity, AgentSocket: os.Getenv("SSH_AUTH_SOCK")}
	s.ActiveGrant = func(write func() error) error { return credentials.WhileSignedIn(cp.login, write) }
	s.BundleKey = func(user string) (keybundle.Context, []byte, error) {
		dek, err := credentials.SyncedKey(cp.login, user)
		if err != nil {
			return keybundle.Context{}, nil, err
		}
		if dek == nil {
			reason, next := "this machine doesn't have your synced keys", "run `tinfoil login --sync`"
			if cp.login == nil {
				reason = "synced keys need a browser login, not an admin API key"
				if source := credentialEnvSource(); source != "" {
					next = "unset " + source + ", then " + next
				}
			}
			return keybundle.Context{}, nil, owner.NoLocalKeys(reason + "; " + next)
		}
		return keybundle.Context{APIOrigin: cp.authOrigin, UserID: user, DEKID: dek.DEKID}, dek.DEK, nil
	}
	if term.IsTerminal(streamFD(streams.in)) {
		s.Passphrase = func(path string) ([]byte, error) {
			fmt.Fprintf(streams.err, "Passphrase for %s: ", path)
			password, err := term.ReadPassword(streamFD(streams.in))
			fmt.Fprintln(streams.err)
			return password, err
		}
	}
	s.Backup = func(path string) {
		fmt.Fprintf(streams.err, "Back up %s: it holds this resource's storage keys, which your SSH key cannot recover.\n", path)
	}
	s.Notify = func(event owner.Event) { renderOwnerEvent(streams, event) }
	s.Progress = func(stage owner.Stage, name string) func() {
		message := "Requesting sandbox attestation through Monitor's relay"
		if stage == owner.SandboxVerifying {
			message = "Verifying sandbox attestation and SSH host key for " + name
		}
		return startConnectionProgress(streams.err, message)
	}
	return s, nil
}

func renderOwnerEvent(streams commandIO, event owner.Event) {
	switch event.Stage {
	case owner.MonitorRunning:
		fmt.Fprintf(streams.err, "Monitor %s: running.\n", event.Name)
	case owner.MonitorVerified:
		fmt.Fprintf(streams.err, "Monitor %s attestation verified.\n", event.Name)
	case owner.MonitorConnecting:
		fmt.Fprintln(streams.err, "Connecting to Monitor "+event.Name+" over attested SSH")
	case owner.MonitorUnlocking:
		fmt.Fprintln(streams.err, "Unlocking Monitor "+event.Name+" encrypted state")
	case owner.MonitorUnlocked:
		fmt.Fprintf(streams.err, "Monitor %s unlocked.\n", event.Name)
	case owner.MonitorCheckpointFailed:
		fmt.Fprintf(streams.err, "Warning: Monitor generation %d is saved only on this machine; synchronizing it to your key bundle failed: %v\n", event.Generation, humanControlplaneError(event.Err))
	case owner.SandboxVerified:
		fmt.Fprintf(streams.err, "Sandbox %s attestation verified.\n", event.Name)
	case owner.SandboxDirectVerified:
		fmt.Fprintf(streams.err, "Sandbox %s attestation verified.\nWarning: sandbox has NO_MONITOR=1; its network traffic is not being tunneled through Monitor.\n", event.Name)
	case owner.SandboxRegistering:
		fmt.Fprintln(streams.err, "Registering sandbox "+event.Name+" with Monitor")
	case owner.SandboxRelinking:
		fmt.Fprintln(streams.err, "Re-linking sandbox "+event.Name+" to the current Monitor boot")
	case owner.SandboxUnlocking:
		fmt.Fprintln(streams.err, "Unlocking sandbox "+event.Name+" encrypted workspace")
	case owner.SandboxPrepared:
		fmt.Fprintf(streams.err, "Prepared %s over attested SSH.\n", event.Name)
	}
}

func ownerWorkload(target *workloadTarget) *owner.Workload {
	return &owner.Workload{Container: target.containerView, Source: target.source, Environment: target.env}
}

type ownerVerifier struct {
	streams  commandIO
	rootOpts *rootOptions
}

func (v ownerVerifier) MonitorHost(domain, source string) (ssh.PublicKey, error) {
	return attestedHostKey(v.streams, v.rootOpts, domain, source, "")
}
func (v ownerVerifier) DirectEvidence(ctx context.Context, domain, source string) (connection.Evidence, error) {
	secure, err := newVerifiedClient(v.rootOpts, domain, source, "")
	if err != nil {
		return nil, err
	}
	verified, err := secure.EnsureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", domain, err)
	}
	return verified, nil
}
func (v ownerVerifier) RelayEvidence(source string, doc, nonce []byte) (connection.Evidence, error) {
	if verify := v.rootOpts.connections.verifySandboxEvidence; verify != nil {
		return verify(doc, nonce, source)
	}
	options, err := verificationOptions(v.rootOpts, source, "")
	if err != nil {
		return nil, err
	}
	return options.Verifier.VerifyV3(doc, nonce, source)
}
