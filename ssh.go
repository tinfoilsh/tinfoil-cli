package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// defaultSSHPort is the host side of the conventional "22:22" mapping, used
// when no container record names a port.
const defaultSSHPort = 22

var (
	sshUser string
	sshPort uint
)

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&sshUser, "user", "l", "root", "Remote user to log in as")
	sshCmd.Flags().UintVarP(&sshPort, "port", "p", 0, "Enclave-side SSH port (default: the container's published SSH port, else 22)")
	addTunnelFlags(sshCmd)
	sshCmd.SilenceUsage = true
}

var sshCmd = &cobra.Command{
	Use:   "ssh [container|hostname] [-- ssh arguments...]",
	Short: "SSH into a container through the verified enclave tunnel",
	Long: `Open an SSH session over the enclave's attested TLS connection.

This runs your local ssh with a ProxyCommand of "tinfoil forward --stdio",
so the session is tunnelled through the shim's CONNECT endpoint rather than
exposed on the public internet.

The target is a container name or an enclave hostname (anything containing a
dot), so enclaves with no controlplane record work too. The container must
publish an SSH port in its tinfoil-config.yml, since the shim tunnels nowhere
else; the reserved debug toolbox on 2222 is out of reach and still needs tinctl.

Anything after -- is handed to ssh unchanged, as either options or a remote
command:

  tinfoil ssh my-container
  tinfoil ssh otter-4s7ut6c3.box2.tinfoil.sh -p 2022
  tinfoil ssh my-container -- systemctl status
  tinfoil ssh my-container -- -A -L 5432:localhost:5432`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sshArgs := []string{}
		if dash := cmd.ArgsLenAtDash(); dash >= 0 {
			sshArgs, args = args[dash:], args[:dash]
		}
		if len(args) > 1 {
			return fmt.Errorf("expected at most one container, got %d", len(args))
		}

		var identifier string
		if len(args) == 1 {
			identifier = args[0]
		}
		target, err := resolveTunnelTarget(identifier)
		if err != nil {
			return err
		}

		port := int(sshPort)
		if port == 0 {
			port = target.sshPort
		}
		if port == 0 {
			// A hostname target has no controlplane record to carry a port, so
			// guess and let the shim say if nothing publishes it.
			port = defaultSSHPort
			log.Infof("No SSH port known for %s, trying %d", target.name, port)
		}

		proxy, err := proxyCommand(target, port)
		if err != nil {
			return err
		}

		argv := []string{
			"-o", "ProxyCommand=" + proxy,
			"-o", "UserKnownHostsFile=" + os.DevNull,
			"-o", "StrictHostKeyChecking=no",
			"-l", sshUser,
		}
		options, command := splitSSHArgs(sshArgs)
		argv = append(argv, options...)
		argv = append(argv, target.host)
		argv = append(argv, command...)

		ssh := exec.Command("ssh", argv...)
		ssh.Stdin, ssh.Stdout, ssh.Stderr = os.Stdin, os.Stdout, os.Stderr
		// The key travels in the environment rather than the ProxyCommand line
		// so it stays out of the process table.
		ssh.Env = os.Environ()
		if key := enclaveAPIKey(); key != "" {
			ssh.Env = append(ssh.Env, envAPIKey+"="+key)
		}
		return ssh.Run()
	},
}

// proxyCommand builds the "tinfoil forward --stdio" invocation ssh runs through
// /bin/sh. It names the resolved host rather than the container, so each
// connection re-verifies the enclave without a second controlplane round trip.
func proxyCommand(target *tunnelTarget, port int) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the tinfoil binary: %w", err)
	}

	argv := []string{self, "forward", "--stdio", strconv.Itoa(port), "--host", target.host}
	if target.repo != "" {
		argv = append(argv, "--repo", target.repo)
	}
	// Each connection re-runs the debug check, so the opt-in travels too.
	if allowDebug {
		argv = append(argv, "--allow-debug")
	}

	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " "), nil
}

func splitSSHArgs(args []string) (options, command []string) {
	const sshOptionsTakingAValue = "BbcDEeFIiJLlmOopQRSWw"
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") || args[i] == "-" {
			return args[:i], args[i:]
		}
		if last := args[i][len(args[i])-1]; strings.IndexByte(sshOptionsTakingAValue, last) >= 0 {
			i++
		}
	}
	return args, nil
}
