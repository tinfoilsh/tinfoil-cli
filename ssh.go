package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// defaultSSHPort is the host side of the conventional "22:22" mapping, used
// when no container record names a port.
const defaultSSHPort = 22

// Well inside the shim's tunnel idle timeout, and how a dead path gets noticed.
const sshServerAliveInterval = 60 * time.Second

func newSshCommand(newClient authenticatedClientFactory, forwardOpts *forwardOptions, rootOpts *rootOptions, sshOpts *sshOptions, trustOpts *trustOptions, tunnelOpts *tunnelOptions) *cobra.Command {
	sshCmd := &cobra.Command{
		Use:   "ssh [container|hostname] [-- ssh arguments...]",
		Short: "SSH into a container over its attested connection",
		Example: `  Open a shell
  tinfoil ssh my-container

  Connect to an enclave hostname on another port
  tinfoil ssh otter-4s7ut6c3.box2.tinfoil.sh -p 2022

  Run a remote command
  tinfoil ssh my-container -- systemctl status

  Pass options through to ssh
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
			target, err := resolveTunnelTarget(newClient, commandStreams(cmd), forwardOpts, rootOpts, trustOpts, identifier)
			if err != nil {
				return err
			}

			options, command := splitSSHArgs(sshArgs)
			code, err := runSSH(commandStreams(cmd), rootOpts, tunnelOpts, target, sshTargetPort(target, sshOpts.sshPort), sshOpts.sshUser, options, command)
			return sshExit(code, err)
		},
	}
	sshCmd.Flags().StringVarP(&sshOpts.sshUser, "user", "l", "root", "Remote user to log in as")
	sshCmd.Flags().UintVarP(&sshOpts.sshPort, "port", "p", 0, "Enclave SSH port (default: the published SSH port, else 22)")
	addTunnelFlags(trustOpts, tunnelOpts, sshCmd)
	return sshCmd
}

func sshTargetPort(target *tunnelTarget, override uint) int {
	if override != 0 {
		return int(override)
	}
	if target.sshPort != 0 {
		return target.sshPort
	}
	// A hostname target has no controlplane record to carry a port, so
	// guess and let the shim say if nothing publishes it.
	log.Infof("No SSH port known for %s, trying %d", target.name, defaultSSHPort)
	return defaultSSHPort
}

// runSSH returns ssh's exit status rather than exiting on it, so a caller can
// finish what the session was for before the process ends.
func runSSH(streams commandIO, rootOpts *rootOptions, tunnelOpts *tunnelOptions, target *tunnelTarget, port int, user string, options, command []string) (int, error) {
	argv, err := sshProxyOptions(rootOpts, tunnelOpts, target, port)
	if err != nil {
		return 0, err
	}
	argv = append(argv, "-l", user)
	argv = append(argv, options...)
	argv = append(argv, "-o", "ServerAliveInterval="+strconv.Itoa(int(sshServerAliveInterval/time.Second)), target.host)
	argv = append(argv, command...)
	return runSSHClient(streams, tunnelOpts, "ssh", argv)
}

// sshProxyOptions supplies the same attested connection to ssh and scp.
func sshProxyOptions(rootOpts *rootOptions, tunnelOpts *tunnelOptions, target *tunnelTarget, port int) ([]string, error) {
	proxy, err := proxyCommand(rootOpts, tunnelOpts, target, port)
	if err != nil {
		return nil, err
	}

	// The attested proxy pins the peer, so SSH host keys add no extra check.
	return []string{
		"-o", "ProxyCommand=" + proxy,
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "StrictHostKeyChecking=no",
	}, nil
}

func runSSHClient(streams commandIO, tunnelOpts *tunnelOptions, program string, argv []string) (int, error) {
	client := exec.Command(program, argv...)
	client.Stdin, client.Stdout, client.Stderr = streams.in, streams.out, streams.err
	// Keep the API key out of the ProxyCommand shown in the process table.
	client.Env = os.Environ()
	if key := enclaveAPIKey(tunnelOpts); key != "" {
		client.Env = append(client.Env, envTunnelAPIKey+"="+key)
	}
	// Ctrl-C reaches this process too, and what follows the session needs it
	// alive. Notify rather than Ignore: an ignored signal survives the exec into
	// ssh, which should still take an interrupt of its own.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)

	err := client.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// sshExit hands the client's own status, which it has already explained, to main to
// exit with once it has finished the work every command ends with.
func sshExit(code int, err error) error {
	if err != nil || code == 0 {
		return err
	}
	return &processExit{code: code}
}

type processExit struct{ code int }

func (e *processExit) Error() string { return fmt.Sprintf("process exited with status %d", e.code) }

// proxyCommand builds the "tinfoil forward --stdio" invocation ssh runs through
// /bin/sh. It names the resolved host rather than the container, so each
// connection re-verifies the enclave without a second controlplane round trip.
func proxyCommand(rootOpts *rootOptions, tunnelOpts *tunnelOptions, target *tunnelTarget, port int) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the tinfoil binary: %w", err)
	}

	argv := []string{self, "forward", "--stdio", strconv.Itoa(port), "--enclave", target.host}
	if target.repo != "" {
		argv = append(argv, "--repo", target.repo)
	}
	if rootOpts.publicRegistry {
		argv = append(argv, "--public-registry")
	}
	if rootOpts.localConfigFile != "" {
		path, err := filepath.Abs(rootOpts.localConfigFile)
		if err != nil {
			return "", fmt.Errorf("locating local config: %w", err)
		}
		argv = append(argv, "--config", path)
	}
	if target.sealedTo != "" {
		argv = append(argv, "--sealed-to", target.sealedTo)
	}
	// Each connection re-runs the debug check, so the opt-in travels too.
	if tunnelOpts.allowDebug {
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
