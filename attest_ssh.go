package main

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	// attestedHostKeyID is the measured attested-keys declaration a workload
	// serves as its sshd HostKey.
	attestedHostKeyID = "host-ssh"

	// sshProfileDir holds the generated client config and pins, relative to
	// ~/.ssh so the Include and UserKnownHostsFile lines stay portable.
	sshProfileDir  = "tinfoil"
	sshIncludeLine = "Include " + sshProfileDir + "/config"
)

var (
	attestSSHName     string
	attestSSHUser     string
	attestSSHHost     string
	attestSSHPort     int
	attestSSHIdentity string
	attestSSHSealedTo string
	attestSSHInstall  bool
)

func init() {
	rootCmd.AddCommand(attestSSHCmd)
	flags := attestSSHCmd.Flags()
	flags.StringVar(&attestSSHName, "name", "", "Host alias for the profile (default: the enclave host)")
	flags.StringVar(&attestSSHUser, "user", "root", "Login user written to the profile")
	flags.StringVar(&attestSSHHost, "ssh-host", "", "Hostname ssh dials (default: the enclave host)")
	flags.IntVar(&attestSSHPort, "ssh-port", defaultSSHPort, "Port ssh dials")
	flags.StringVar(&attestSSHIdentity, "identity", "", "IdentityFile written to the profile")
	flags.StringVar(&attestSSHSealedTo, "sealed-to", "", "RTMR3 the enclave must carry, as 48-byte hex")
	flags.BoolVar(&attestSSHInstall, "install", false, "Write the profile under ~/.ssh/"+sshProfileDir+" and include it from ~/.ssh/config")
}

var attestSSHCmd = &cobra.Command{
	Use:   "attest-ssh HOST",
	Short: "Verify an enclave's attested SSH host key and print or install a native ssh profile",
	Long: `Verify HOST against the expected workload given with --repo, read the
attested "host-ssh" public key its quote endorses, and turn it into an ssh
client profile pinned to that key. Nothing is trusted from the SSH connection
itself: a server presenting any other host key fails before authentication.

By default the profile and its known_hosts line are printed and nothing is
written. With --install the profile goes to ~/.ssh/tinfoil/config, the pin to
~/.ssh/tinfoil/known_hosts/<name>, and ~/.ssh/config gains one Include so
"ssh <name>" works without this CLI. Unrelated configuration is preserved.
A pin identifies the key verified now; a CVM reboot rotates it, so rerun
this command after one.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		hostKey, err := attestedHostKey(args[0], repo, attestSSHSealedTo)
		if err != nil {
			return err
		}
		profile := sshProfile{
			name: attestSSHName, hostName: attestSSHHost, port: attestSSHPort,
			user: attestSSHUser, identityFile: attestSSHIdentity, hostKey: hostKey,
		}
		if profile.name == "" {
			profile.name = args[0]
		}
		if profile.hostName == "" {
			profile.hostName = args[0]
		}
		if !attestSSHInstall {
			fmt.Printf("%s\n# %s\n%s\n", profile.render(), profile.pinPath("~/.ssh"), profile.knownHostsLine())
			return nil
		}
		if err := profile.install(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Installed ssh profile %s; connect with: ssh %s\n", profile.name, profile.name)
		return nil
	},
}

// attestedHostKey verifies host against source and returns the endorsed
// host-ssh key. A failed verification yields no key, so callers never fall
// back to unverified host-key acceptance.
func attestedHostKey(host, source, sealedTo string) (ssh.PublicKey, error) {
	secure, err := newVerifiedClient(host, source, sealedTo)
	if err != nil {
		return nil, err
	}
	verified, err := secure.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", host, err)
	}
	if !time.Now().Before(verified.FreshnessExpiresAt) {
		return nil, fmt.Errorf("verification of %s is no longer fresh", host)
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
	hostKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("attested %q key cannot be an SSH host key: %w", attestedHostKeyID, err)
	}
	return hostKey, nil
}

type sshProfile struct {
	name         string
	hostName     string
	port         int
	user         string
	identityFile string
	hostKey      ssh.PublicKey
}

func (p sshProfile) pinPath(sshDir string) string {
	return filepath.Join(sshDir, sshProfileDir, "known_hosts", p.name)
}

func (p sshProfile) knownHostsLine() string {
	address := knownhosts.Normalize(net.JoinHostPort(p.hostName, strconv.Itoa(p.port)))
	return knownhosts.Line([]string{address}, p.hostKey)
}

func (p sshProfile) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n  HostName %s\n  Port %d\n  User %s\n", p.name, p.hostName, p.port, p.user)
	if p.identityFile != "" {
		fmt.Fprintf(&b, "  IdentityFile %s\n  IdentitiesOnly yes\n", p.identityFile)
	}
	fmt.Fprintf(&b, "  HostKeyAlgorithms %s\n", p.hostKey.Type())
	fmt.Fprintf(&b, "  UserKnownHostsFile %s\n", p.pinPath("~/.ssh"))
	b.WriteString("  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  CheckHostIP no\n")
	return b.String()
}

func (p sshProfile) install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locating home directory: %w", err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Dir(p.pinPath(sshDir)), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(p.pinPath(sshDir), []byte(p.knownHostsLine()+"\n")); err != nil {
		return err
	}
	configPath := filepath.Join(sshDir, sshProfileDir, "config")
	existing, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeFileAtomic(configPath, replaceHostBlock(existing, p.name, p.render())); err != nil {
		return err
	}
	return ensureInclude(filepath.Join(sshDir, "config"))
}

// replaceHostBlock swaps the single-alias `Host name` block in a config this
// CLI owns; a block runs from its Host line to the next one.
func replaceHostBlock(config []byte, name, block string) []byte {
	var out strings.Builder
	skipping := false
	for _, line := range strings.SplitAfter(string(config), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && strings.EqualFold(fields[0], "Host") {
			skipping = len(fields) == 2 && fields[1] == name
		}
		if !skipping {
			out.WriteString(line)
		}
	}
	kept := strings.TrimRight(out.String(), "\n")
	if kept != "" {
		kept += "\n\n"
	}
	return []byte(kept + block)
}

// ensureInclude puts the Include before any Host or Match block, where ssh
// applies it to every connection.
func ensureInclude(path string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(existing), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Host") || strings.EqualFold(fields[0], "Match") {
			break
		}
		if strings.Join(fields, " ") == sshIncludeLine {
			return nil
		}
	}
	return writeFileAtomic(path, append([]byte(sshIncludeLine+"\n\n"), existing...))
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
