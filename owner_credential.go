package main

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

func ownerService(cp *cpClient) (*owner.Service, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	credentials, err := authService()
	if err != nil {
		return nil, err
	}
	s := &owner.Service{ConfigPath: path, Home: os.UserHomeDir, IdentityFile: attestSSHIdentity, AgentSocket: os.Getenv("SSH_AUTH_SOCK")}
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
		return keybundle.Context{APIOrigin: fixedAPIOrigin, UserID: user, DEKID: dek.DEKID}, dek.DEK, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		s.Passphrase = func(path string) ([]byte, error) {
			fmt.Fprintf(os.Stderr, "Passphrase for %s: ", path)
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return password, err
		}
	}
	s.Backup = func(path string) {
		fmt.Fprintf(os.Stderr, "Back up %s: it holds this resource's storage keys, which your SSH key cannot recover.\n", path)
	}
	s.Notify = renderOwnerEvent
	s.Progress = func(stage owner.Stage, name string) func() {
		message := "Requesting sandbox attestation through Monitor's relay"
		if stage == owner.SandboxVerifying {
			message = "Verifying sandbox attestation and SSH host key for " + name
		}
		return startConnectionProgress(os.Stderr, message)
	}
	return s, nil
}

func renderOwnerEvent(event owner.Event) {
	switch event.Stage {
	case owner.MonitorRunning:
		fmt.Fprintf(os.Stderr, "Monitor %s: running.\n", event.Name)
	case owner.MonitorVerified:
		fmt.Fprintf(os.Stderr, "Monitor %s attestation verified.\n", event.Name)
	case owner.MonitorConnecting:
		fmt.Fprintln(os.Stderr, "Connecting to Monitor "+event.Name+" over attested SSH")
	case owner.MonitorUnlocking:
		fmt.Fprintln(os.Stderr, "Unlocking Monitor "+event.Name+" encrypted state")
	case owner.MonitorUnlocked:
		fmt.Fprintf(os.Stderr, "Monitor %s unlocked.\n", event.Name)
	case owner.MonitorCheckpointFailed:
		fmt.Fprintf(os.Stderr, "Warning: Monitor generation %d is saved only on this machine; synchronizing it to your key bundle failed: %v\n", event.Generation, humanControlplaneError(event.Err))
	case owner.SandboxVerified:
		fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\n", event.Name)
	case owner.SandboxDirectVerified:
		fmt.Fprintf(os.Stderr, "Sandbox %s attestation verified.\nWarning: sandbox has NO_MONITOR=1; its network traffic is not being tunneled through Monitor.\n", event.Name)
	case owner.SandboxRegistering:
		fmt.Fprintln(os.Stderr, "Registering sandbox "+event.Name+" with Monitor")
	case owner.SandboxRelinking:
		fmt.Fprintln(os.Stderr, "Re-linking sandbox "+event.Name+" to the current Monitor boot")
	case owner.SandboxUnlocking:
		fmt.Fprintln(os.Stderr, "Unlocking sandbox "+event.Name+" encrypted workspace")
	case owner.SandboxPrepared:
		fmt.Fprintf(os.Stderr, "Prepared %s over attested SSH.\n", event.Name)
	}
}

func ownerWorkload(target *workloadTarget) *owner.Workload {
	return &owner.Workload{Container: target.containerView, Source: target.source, Environment: target.env}
}

type ownerVerifier struct{}

func (ownerVerifier) MonitorHost(domain, source string) (ssh.PublicKey, error) {
	return attestedHostKey(domain, source, "")
}
func (ownerVerifier) DirectEvidence(ctx context.Context, domain, source string) (connection.Evidence, error) {
	secure, err := newVerifiedClient(domain, source, "")
	if err != nil {
		return nil, err
	}
	verified, err := secure.EnsureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", domain, err)
	}
	return verified, nil
}
func (ownerVerifier) RelayEvidence(source string, doc, nonce []byte) (connection.Evidence, error) {
	options, err := verificationOptions(source, "")
	if err != nil {
		return nil, err
	}
	return options.Verifier.VerifyV3(doc, nonce, source)
}
