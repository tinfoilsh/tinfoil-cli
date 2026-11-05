package owner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"golang.org/x/crypto/ssh"
)

type Service struct {
	ConfigPath   string
	Home         func() (string, error)
	IdentityFile string
	AgentSocket  string
	BundleKey    func(userID string) (keybundle.Context, []byte, error)
	ActiveGrant  func(func() error) error
	Passphrase   func(path string) ([]byte, error)
	Backup       func(path string)
	Notify       func(Event)
	Progress     func(Stage, string) func()
}

type Stage string

const (
	MonitorRunning          Stage = "monitor-running"
	MonitorVerified         Stage = "monitor-verified"
	MonitorConnecting       Stage = "monitor-connecting"
	MonitorUnlocking        Stage = "monitor-unlocking"
	MonitorUnlocked         Stage = "monitor-unlocked"
	MonitorCheckpointFailed Stage = "monitor-checkpoint-failed"
	SandboxVerifying        Stage = "sandbox-verifying"
	SandboxRelayVerifying   Stage = "sandbox-relay-verifying"
	SandboxVerified         Stage = "sandbox-verified"
	SandboxDirectVerified   Stage = "sandbox-direct-verified"
	SandboxRegistering      Stage = "sandbox-registering"
	SandboxRelinking        Stage = "sandbox-relinking"
	SandboxUnlocking        Stage = "sandbox-unlocking"
	SandboxPrepared         Stage = "sandbox-prepared"
)

type Event struct {
	Stage      Stage
	Name       string
	Generation uint64
	Err        error
}

func (s *Service) notify(stage Stage, name string) {
	if s != nil && s.Notify != nil {
		s.Notify(Event{Stage: stage, Name: name})
	}
}

func (s *Service) progress(stage Stage, name string) func() {
	if s != nil && s.Progress != nil {
		return s.Progress(stage, name)
	}
	return func() {}
}

func (s *Service) activeGrant(write func() error) error {
	if s.ActiveGrant == nil {
		return errors.New("you signed out while connecting; run `tinfoil login --sync`")
	}
	return s.ActiveGrant(write)
}

func validLowerUUID(id string) bool {
	return resourceIDPattern.MatchString(id) && id == strings.ToLower(id)
}

func requireRunningConnection(kind string, row controlplane.Container) error {
	if row.Status == "running" {
		return nil
	}
	next := "status " + row.Name + " --watch"
	if row.Status == "stopped" || row.Status == "failed" {
		next = "start " + row.Name
	}
	label := "-"
	if row.Status != "" {
		label = strings.ToUpper(row.Status[:1]) + row.Status[1:]
	}
	if row.Status == "started" {
		label = "Starting"
	}
	return fmt.Errorf("%s %s is %s; run `tinfoil %s %s`", kind, row.Name, label, strings.ToLower(kind), next)
}

type Verifier interface {
	MonitorHost(domain, source string) (ssh.PublicKey, error)
	DirectEvidence(context.Context, string, string) (connection.Evidence, error)
	RelayEvidence(source string, document, nonce []byte) (connection.Evidence, error)
}

// Workload keeps the reviewed configuration reference and measured environment
// with the exact API resource selected by the command.
type Workload struct {
	controlplane.Container
	Source      string
	Environment map[string]string
}

type ConnectionInfo struct {
	Name, HostName, User, IdentityFile, HostKeyAlias, ResourceID string
	Port                                                         int
	HostKey                                                      ssh.PublicKey
	Jump                                                         *ConnectionInfo
	NoAgent                                                      bool
}

type mkContext = keybundle.Context
type mkPayload = keybundle.Payload
type mkResource = keybundle.Resource
type mkBinding = keybundle.Binding
type b64u = keybundle.Base64URL

const (
	monitorDeviceKeyName = "device_ed25519"
	tmkOwnerKeyName      = "owner_tmk_ed25519"
	sandboxLoginUser     = "sandbox"
	monitorSSHUser       = "device"
	monitorJumpSuffix    = ".monitor"
	defaultSSHPort       = 22
	maxConnectionPort    = 65535
)
