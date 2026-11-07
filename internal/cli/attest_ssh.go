package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// managedSSHHost forwards controlplane-assigned SSH ports to their enclaves.
const managedSSHHost = "debug.tinfoil.sh"

// Profiles live under ~/.ssh so the Include and UserKnownHostsFile paths stay relative.
const sshIncludeGlob = "tinfoil/*.conf"

// sshProfileNamePattern keeps a profile name a literal ssh Host alias and a single path component.
var sshProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

func newAttestSSHCommand(newClient authenticatedClientFactory, newScope scopeClientFactory, attestSSHOpts *attestSSHOptions, forwardOpts *forwardOptions, identityOpts *identityOptions, rootOpts *rootOptions, trustOpts *trustOptions) *cobra.Command {
	attestSSHCmd := &cobra.Command{
		Use:   "attest-ssh [container|hostname]",
		Short: "Pin an enclave's attested SSH host key for native ssh",
		Long: `Print an ssh profile pinned to the attested host key, or write it with --install.
A reboot rotates the key, so rerun this after one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := startConnectionProgress(cmd.ErrOrStderr(), "Looking up "+args[0])
			target, err := resolveTunnelTarget(newClient, commandStreams(cmd), forwardOpts, rootOpts, trustOpts, args[0])
			resolved()
			if err != nil {
				return err
			}
			if target.container != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s.\n", target.name, statusLabel(target.container.Status))
				switch target.container.Repo {
				case monitorRepo:
					return fmt.Errorf("Perimeter has no interactive shell; use tinfoil perimeter open %s", target.name)
				case defaultSandboxRepo:
					if attestSSHOpts.attestSSHHost != "" || attestSSHOpts.attestSSHPort != 0 {
						return errors.New("managed bunkers use their configured SSH endpoint")
					}
					if attestSSHOpts.attestSSHName != "" && !sshProfileNamePattern.MatchString(attestSSHOpts.attestSSHName) {
						return errors.New("invalid SSH profile name")
					}
					s, err := connectSandbox(newScope, commandStreams(cmd), identityOpts, rootOpts, trustOpts, cmd.Context(), target.workload)
					if err != nil {
						return err
					}
					defer s.close()
					if err := s.enroll(cmd.Context()); err != nil {
						return err
					}
					if attestSSHOpts.attestSSHName != "" {
						s.profile.name = attestSSHOpts.attestSSHName
						if s.profile.jump != nil {
							s.profile.jump.name = attestSSHOpts.attestSSHName + monitorJumpSuffix
						}
					}
					if cmd.Flags().Changed("user") {
						s.profile.user = attestSSHOpts.attestSSHUser
					}
					if attestSSHOpts.attestSSHInstall {
						return s.install(commandStreams(cmd))
					}
					fmt.Fprintf(commandStreams(cmd).out, "%s\n# ~/.ssh/tinfoil/%s.known_hosts\n%s", s.profile.render(), s.profile.name, s.profile.pin())
					return nil
				}
			}
			profile := sshProfile{name: attestSSHOpts.attestSSHName, hostName: nativeSSHHost(target, attestSSHOpts.attestSSHHost), port: sshTargetPort(target, attestSSHOpts.attestSSHPort), user: attestSSHOpts.attestSSHUser, identityFile: identityOpts.attestSSHIdentity}
			if profile.name == "" {
				profile.name = target.name
			}
			if !sshProfileNamePattern.MatchString(profile.name) {
				return fmt.Errorf("invalid profile name %q: use letters, digits, dots, dashes or underscores, starting with a letter or digit", profile.name)
			}
			if profile.port > 65535 {
				return fmt.Errorf("--ssh-port must be at most 65535 (got %d)", profile.port)
			}
			if profile.hostKey, err = attestedHostKey(commandStreams(cmd), rootOpts, target.host, target.repo, target.sealedTo); err != nil {
				return err
			}
			fmt.Fprintln(commandStreams(cmd).err, "Attestation successful.")
			if !attestSSHOpts.attestSSHInstall {
				fmt.Fprintf(commandStreams(cmd).out, "%s\n# ~/.ssh/tinfoil/%s.known_hosts\n%s", profile.render(), profile.name, profile.pin())
				return nil
			}
			return profile.install(commandStreams(cmd), attestSSHOpts)
		},
	}
	flags := attestSSHCmd.Flags()
	flags.StringVar(&attestSSHOpts.attestSSHName, "name", "", "Host alias for the profile (default: HOST)")
	flags.StringVar(&attestSSHOpts.attestSSHHost, "ssh-host", "", "Hostname ssh dials (default: debug.tinfoil.sh for a container with a published SSH port, else HOST)")
	flags.StringVar(&attestSSHOpts.attestSSHUser, "user", "root", "Login user written to the profile")
	flags.UintVar(&attestSSHOpts.attestSSHPort, "ssh-port", 0, "Port ssh dials (default: the container's published SSH port, else 22)")
	flags.StringVar(&identityOpts.attestSSHIdentity, "identity", "", "IdentityFile written to the profile")
	flags.BoolVar(&attestSSHOpts.attestSSHInstall, "install", false, "Write the profile under ~/.ssh/tinfoil instead of printing it")
	flags.BoolVar(&attestSSHOpts.attestSSHYes, "yes", false, "Add Include "+sshIncludeGlob+" to ~/.ssh/config without prompting")
	addTrustDangerousFlag(trustOpts, attestSSHCmd)
	return attestSSHCmd
}

// Stop and join the reporter before the next step or credential prompt.
func startConnectionProgress(out io.Writer, message string) func() {
	fmt.Fprintln(out, message)
	ticker := time.NewTicker(10 * time.Second)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fmt.Fprintln(out, message+" (still waiting)")
			}
		}
	}()
	return sync.OnceFunc(func() { close(stop); <-done })
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
func attestedHostKey(streams commandIO, rootOpts *rootOptions, host, source, sealedTo string) (ssh.PublicKey, error) {
	defer startConnectionProgress(streams.err, "Verifying attestation and SSH host key for "+host)()
	input, err := verificationInput(rootOpts, source, sealedTo)
	if err != nil {
		return nil, err
	}
	return connection.AttestedHostKey(context.Background(), host, input)
}

type attestedEvidence = connection.Evidence

func endorsedHostKey(host string, verified attestedEvidence) (ssh.PublicKey, error) {
	return connection.EndorsedHostKey(host, verified)
}

type sshProfile struct {
	resourceID   string
	name         string
	hostName     string
	port         int
	user         string
	identityFile string
	hostKey      ssh.PublicKey
	// hostKeyAlias pins hostKey under a name instead of the dialed address, and
	// jump is the host this one is reached through.
	hostKeyAlias string
	jump         *sshProfile
	// noAgent keeps ssh-agent keys out of this hop. OpenSSH offers agent keys
	// that match any IdentityFile (including one from a user's Host * block)
	// before key files, so identityFile alone does not decide which key is sent.
	noAgent bool
}

func (p sshProfile) render() string {
	marker := ""
	if p.resourceID != "" {
		marker = "# tinfoil-resource: " + p.resourceID + "\n"
	}
	if p.jump == nil {
		return marker + p.block(p.name)
	}
	return marker + p.jump.block(p.name) + "\n" + p.block(p.name)
}

// block renders one Host whose pins are in pins.known_hosts.
func (p sshProfile) block(pins string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n  HostName %s\n  Port %d\n  User %s\n", p.name, p.hostName, p.port, p.user)
	if p.jump != nil {
		fmt.Fprintf(&b, "  ProxyJump %s\n", p.jump.name)
	}
	if p.hostKeyAlias != "" {
		fmt.Fprintf(&b, "  HostKeyAlias %s\n", p.hostKeyAlias)
	}
	if p.identityFile != "" {
		identity := p.identityFile
		if strings.ContainsAny(identity, " \t\r\n\"\\") {
			identity = strconv.Quote(identity)
		}
		fmt.Fprintf(&b, "  IdentityFile %s\n  IdentitiesOnly yes\n", identity)
	}
	if p.noAgent {
		b.WriteString("  IdentityAgent none\n")
	}
	fmt.Fprintf(&b, "  HostKeyAlgorithms %s\n  UserKnownHostsFile ~/.ssh/tinfoil/%s.known_hosts\n", p.hostKey.Type(), pins)
	b.WriteString("  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  CheckHostIP no\n")
	return b.String()
}

func (p sshProfile) pin() string {
	address := p.hostKeyAlias
	if address == "" {
		address = knownhosts.Normalize(net.JoinHostPort(p.hostName, strconv.Itoa(p.port)))
	}
	pin := knownhosts.Line([]string{address}, p.hostKey) + "\n"
	if p.jump != nil {
		pin = p.jump.pin() + pin
	}
	return pin
}

func (p sshProfile) install(streams commandIO, attestSSHOpts *attestSSHOptions) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return p.installTo(home, streams.in, streams.err, term.IsTerminal(streamFD(streams.in)), attestSSHOpts.attestSSHYes)
}

func (p sshProfile) installTo(home string, in io.Reader, out io.Writer, interactive, autoYes bool) error {
	dir := filepath.Join(home, ".ssh", "tinfoil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	confPath := filepath.Join(dir, p.name+".conf")
	_, err := os.Lstat(confPath)
	updated := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, p.name+".known_hosts"), []byte(p.pin())); err != nil {
		return err
	}
	if err := writeAtomic(confPath, []byte(p.render())); err != nil {
		return err
	}
	action := "Added"
	if updated {
		action = "Updated"
	}
	fmt.Fprintf(out, "%s SSH profile %s (~/.ssh/tinfoil/%s.conf).\n", action, p.name, p.name)
	if err := offerSSHInclude(filepath.Join(home, ".ssh", "config"), in, out, interactive, autoYes); err != nil {
		return err
	}
	fmt.Fprintf(out, "Connect with: ssh %s\n", p.name)
	return nil
}

// offerSSHInclude checks for a top-level Include first. If the line is
// already there, it returns without printing or writing. Otherwise it
// prompts (or honors --yes) and prepends the line.
func offerSSHInclude(path string, in io.Reader, out io.Writer, interactive, autoYes bool) error {
	existing, err := readSSHConfig(path)
	if err != nil {
		return err
	}
	if hasTopLevelInclude(existing) {
		return nil
	}
	add := autoYes
	if !add {
		if !interactive {
			printSSHIncludeHelp(out)
			return nil
		}
		add, err = promptAddSSHInclude(in, out)
		if err != nil {
			return err
		}
	}
	if !add {
		printSSHIncludeHelp(out)
		return nil
	}
	if err := writeAtomic(path, append([]byte(sshIncludeLine()+"\n\n"), existing...)); err != nil {
		return err
	}
	fmt.Fprintf(out, "Added %s to ~/.ssh/config.\n", sshIncludeLine())
	return nil
}

func readSSHConfig(path string) ([]byte, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return existing, nil
}

func sshIncludeLine() string {
	return "Include " + sshIncludeGlob
}

func promptAddSSHInclude(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprintf(out, "For your SSH client to use this profile, ~/.ssh/config needs this line before any Host or Match block:\n\n%s\n\nAdd it now? [y/N] ", sshIncludeLine())
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

func printSSHIncludeHelp(out io.Writer) {
	fmt.Fprintf(out, "Note: For your SSH client to use this profile, add this line at the top of ~/.ssh/config:\n\n%s\n\nIt must appear before any Host or Match block.\n", sshIncludeLine())
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
	return statefile.Replace(path, data)
}
