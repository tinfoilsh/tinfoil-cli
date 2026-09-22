package main

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// attestedHostKeyID is the attested-keys declaration a workload serves as its sshd HostKey.
const attestedHostKeyID = "host-ssh"

// managedSSHHost forwards controlplane-assigned SSH ports to their enclaves.
const managedSSHHost = "console.tinfoil.sh"

// Profiles live under ~/.ssh so the Include and UserKnownHostsFile paths stay relative.
const sshIncludeGlob = "tinfoil/*.conf"

// sshProfileNamePattern keeps a profile name a literal ssh Host alias and a single path component.
var sshProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

var (
	attestSSHName     string
	attestSSHHost     string
	attestSSHUser     string
	attestSSHPort     uint
	attestSSHIdentity string
	attestSSHInstall  bool
)

func init() {
	rootCmd.AddCommand(attestSSHCmd)
	flags := attestSSHCmd.Flags()
	flags.StringVar(&attestSSHName, "name", "", "Host alias for the profile (default: HOST)")
	flags.StringVar(&attestSSHHost, "ssh-host", "", "Hostname ssh dials (default: console.tinfoil.sh for a container with a published SSH port, else HOST)")
	flags.StringVar(&attestSSHUser, "user", "root", "Login user written to the profile")
	flags.UintVar(&attestSSHPort, "ssh-port", 0, "Port ssh dials (default: the container's published SSH port, else 22)")
	flags.StringVar(&attestSSHIdentity, "identity", "", "IdentityFile written to the profile")
	flags.BoolVar(&attestSSHInstall, "install", false, "Write the profile under ~/.ssh/tinfoil instead of printing it")
}

var attestSSHCmd = &cobra.Command{
	Use:   "attest-ssh [container|hostname]",
	Short: "Print or install a native ssh profile pinned to an enclave's attested host key",
	Long: `Resolve a container name or enclave hostname, verify it against its recorded
repo or --repo, read the attested "host-ssh" key its quote endorses, and print an
ssh profile pinned to it. With --install the profile is written to
~/.ssh/tinfoil/<name>.conf and included from ~/.ssh/config. A CVM reboot
rotates the key, so rerun this command after one.

Containers with a published SSH port connect through console.tinfoil.sh.
Bare hostname targets connect directly. --ssh-host overrides the SSH endpoint;
attestation always uses the enclave hostname.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := resolveTunnelTarget(args[0])
		if err != nil {
			return err
		}
		profile := sshProfile{name: attestSSHName, hostName: nativeSSHHost(target, attestSSHHost), port: sshTargetPort(target, attestSSHPort), user: attestSSHUser, identityFile: attestSSHIdentity}
		if profile.name == "" {
			profile.name = target.name
		}
		if !sshProfileNamePattern.MatchString(profile.name) {
			return fmt.Errorf("invalid profile name %q: use letters, digits, dots, dashes or underscores, starting with a letter or digit", profile.name)
		}
		if profile.port > 65535 {
			return fmt.Errorf("--ssh-port must be at most 65535 (got %d)", profile.port)
		}
		if profile.hostKey, err = attestedHostKey(target.host, target.repo, target.sealedTo); err != nil {
			return err
		}
		if !attestSSHInstall {
			fmt.Printf("%s\n# ~/.ssh/tinfoil/%s.known_hosts\n%s", profile.render(), profile.name, profile.pin())
			return nil
		}
		return profile.install()
	},
}

func nativeSSHHost(target *tunnelTarget, override string) string {
	if override != "" {
		return override
	}
	if target.sshPort > 0 {
		return managedSSHHost
	}
	return target.host
}

// attestedHostKey verifies host against source and returns the endorsed
// host-ssh key, so a failed verification never falls back to unverified acceptance.
func attestedHostKey(host, source, sealedTo string) (ssh.PublicKey, error) {
	secure, err := newVerifiedClient(host, source, sealedTo)
	if err != nil {
		return nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", host, err)
	}
	data, err := verified.CryptoMaterialData(attestedHostKeyID, envelope.KeySPKIV1Format)
	if err != nil {
		return nil, fmt.Errorf("%s endorses no attested %q key: %w", host, attestedHostKeyID, err)
	}
	der, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("attested %q key is not hex: %w", attestedHostKeyID, err)
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("attested %q key is not SPKI: %w", attestedHostKeyID, err)
	}
	return ssh.NewPublicKey(public)
}

type sshProfile struct {
	name         string
	hostName     string
	port         int
	user         string
	identityFile string
	hostKey      ssh.PublicKey
}

func (p sshProfile) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n  HostName %s\n  Port %d\n  User %s\n", p.name, p.hostName, p.port, p.user)
	if p.identityFile != "" {
		fmt.Fprintf(&b, "  IdentityFile %s\n  IdentitiesOnly yes\n", p.identityFile)
	}
	fmt.Fprintf(&b, "  HostKeyAlgorithms %s\n  UserKnownHostsFile ~/.ssh/tinfoil/%s.known_hosts\n", p.hostKey.Type(), p.name)
	b.WriteString("  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  CheckHostIP no\n")
	return b.String()
}

func (p sshProfile) pin() string {
	address := knownhosts.Normalize(net.JoinHostPort(p.hostName, strconv.Itoa(p.port)))
	return knownhosts.Line([]string{address}, p.hostKey) + "\n"
}

func (p sshProfile) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh", "tinfoil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, p.name+".known_hosts"), []byte(p.pin())); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, p.name+".conf"), []byte(p.render())); err != nil {
		return err
	}
	if err := ensureInclude(filepath.Join(home, ".ssh", "config")); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Installed ssh profile %s; connect with: ssh %s\n", p.name, p.name)
	return nil
}

// ensureInclude puts the Include first, before any Host block could scope it.
func ensureInclude(path string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hasTopLevelInclude(existing) {
		return nil
	}
	return writeAtomic(path, append([]byte("Include "+sshIncludeGlob+"\n\n"), existing...))
}

// Only an uncommented Include before the first Host or Match block applies to every host.
func hasTopLevelInclude(config []byte) bool {
	for _, line := range strings.Split(string(config), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host", "match":
			return false
		case "include":
			for _, glob := range fields[1:] {
				if glob == sshIncludeGlob {
					return true
				}
			}
		}
	}
	return false
}

// A predictable temp name lets anyone who can write the directory pre-create a symlink we would follow.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
