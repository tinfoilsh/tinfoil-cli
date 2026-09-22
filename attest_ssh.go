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

// Profiles live under ~/.ssh so the Include and UserKnownHostsFile paths stay relative.
const sshIncludeLine = "Include tinfoil/*.conf"

// sshProfileNamePattern keeps a profile name a literal ssh Host alias and a single path component.
var sshProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

var (
	attestSSHName     string
	attestSSHUser     string
	attestSSHPort     int
	attestSSHIdentity string
)

func init() {
	rootCmd.AddCommand(attestSSHCmd)
	flags := attestSSHCmd.Flags()
	flags.StringVar(&attestSSHName, "name", "", "Host alias for the profile (default: HOST)")
	flags.StringVar(&attestSSHUser, "user", "root", "Login user written to the profile")
	flags.IntVar(&attestSSHPort, "ssh-port", defaultSSHPort, "Port ssh dials")
	flags.StringVar(&attestSSHIdentity, "identity", "", "IdentityFile written to the profile")
}

var attestSSHCmd = &cobra.Command{
	Use:   "attest-ssh HOST",
	Short: "Install a native ssh profile pinned to an enclave's attested host key",
	Long: `Verify HOST against --repo, read the attested "host-ssh" key its quote
endorses, and write ~/.ssh/tinfoil/<name>.conf pinned to it, included from
~/.ssh/config. A CVM reboot rotates the key, so rerun this command after one.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		profile := sshProfile{name: attestSSHName, hostName: args[0], port: attestSSHPort, user: attestSSHUser, identityFile: attestSSHIdentity}
		if profile.name == "" {
			profile.name = args[0]
		}
		if !sshProfileNamePattern.MatchString(profile.name) {
			return fmt.Errorf("invalid profile name %q: use letters, digits, dots, dashes or underscores, starting with a letter or digit", profile.name)
		}
		if profile.port < 1 || profile.port > 65535 {
			return fmt.Errorf("--ssh-port must be between 1 and 65535 (got %d)", profile.port)
		}
		var err error
		if profile.hostKey, err = attestedHostKey(args[0], repo, ""); err != nil {
			return err
		}
		return profile.install()
	},
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

func (p sshProfile) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh", "tinfoil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	address := knownhosts.Normalize(net.JoinHostPort(p.hostName, strconv.Itoa(p.port)))
	pin := knownhosts.Line([]string{address}, p.hostKey) + "\n"
	if err := os.WriteFile(filepath.Join(dir, p.name+".known_hosts"), []byte(pin), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, p.name+".conf"), []byte(p.render()), 0o600); err != nil {
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
	if strings.Contains(string(existing), sshIncludeLine) {
		return nil
	}
	tmp := path + ".tinfoil.tmp"
	if err := os.WriteFile(tmp, append([]byte(sshIncludeLine+"\n\n"), existing...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
