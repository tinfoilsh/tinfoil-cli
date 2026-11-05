package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newSCPCommand(newClient authenticatedClientFactory, forwardOpts *forwardOptions, rootOpts *rootOptions, trustOpts *trustOptions, tunnelOpts *tunnelOptions) *cobra.Command {
	var user string
	var port uint
	cmd := &cobra.Command{
		Use:   "scp <source>... <destination> [-- scp options...]",
		Short: "Copy files through the verified enclave tunnel",
		Long: `Remote paths are [user@]container:path or [user@]hostname:path.
Put native scp options after --; -p before -- is the enclave SSH port.`,
		Example: `  Upload a file
  tinfoil scp ./file.txt my-container:/tmp/

  Download a file
  tinfoil scp my-container:/var/log/app.log ./app.log

  Copy a directory, passing -r to scp
  tinfoil scp ./data my-container:/data -- -r

  Copy to an enclave hostname as another user and port
  tinfoil scp ./file.txt ubuntu@enclave.example.com:/tmp/ -p 2022

  Choose the enclave with --enclave
  tinfoil scp --enclave enclave.example.com ./file.txt :/tmp/`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var options []string
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				options, args = args[dash:], args[:dash]
			}
			if len(args) < 2 {
				return fmt.Errorf("expected at least one source and a destination")
			}
			if port > 65535 {
				return fmt.Errorf("invalid --port %d: must be 1..65535", port)
			}
			target, paths, err := resolveSCPPaths(newClient, commandStreams(cmd), forwardOpts, rootOpts, trustOpts, args, user)
			if err != nil {
				return err
			}
			code, err := runSCP(commandStreams(cmd), rootOpts, tunnelOpts, target, sshTargetPort(target, port), options, paths)
			return sshExit(code, err)
		},
	}
	cmd.Flags().StringVarP(&user, "user", "l", "root", "Remote user to log in as")
	cmd.Flags().UintVarP(&port, "port", "p", 0, "Enclave SSH port (default: the published SSH port, else 22)")
	addTunnelFlags(trustOpts, tunnelOpts, cmd)
	return cmd
}

type scpPath struct {
	remote     bool
	identifier string
	user       string
	path       string
}

func parseSCPPath(raw string) (scpPath, error) {
	if strings.HasPrefix(raw, "scp://") {
		return scpPath{}, fmt.Errorf("use [user@]container:path or [user@]hostname:path instead of an scp:// URI")
	}
	host, path, remote := strings.Cut(raw, ":")
	// A slash before the colon makes this an explicit local path, as in scp.
	if !remote || strings.Contains(host, "/") {
		return scpPath{path: raw}, nil
	}
	var user string
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		user, host = host[:at], host[at+1:]
		if user == "" {
			return scpPath{}, fmt.Errorf("empty remote user in %q", raw)
		}
	}
	return scpPath{remote: true, identifier: host, user: user, path: path}, nil
}

func resolveSCPPaths(newClient authenticatedClientFactory, streams commandIO, forwardOpts *forwardOptions, rootOpts *rootOptions, trustOpts *trustOptions, args []string, user string) (*tunnelTarget, []string, error) {
	paths := make([]scpPath, len(args))
	var identifier string
	hasRemote := false
	for i, raw := range args {
		path, err := parseSCPPath(raw)
		if err != nil {
			return nil, nil, err
		}
		paths[i] = path
		if !path.remote {
			continue
		}
		if path.identifier == "" {
			path.identifier = rootOpts.enclaveHost
		}
		if path.identifier == "" {
			return nil, nil, fmt.Errorf("name a container or hostname before ':', or pass --enclave")
		}
		if hasRemote && path.identifier != identifier {
			return nil, nil, fmt.Errorf("all remote paths must name the same container or hostname")
		}
		identifier, hasRemote = path.identifier, true
	}
	if !hasRemote {
		return nil, nil, fmt.Errorf("at least one path must be remote: use container:path or hostname:path")
	}
	if paths[len(paths)-1].remote {
		for _, path := range paths[:len(paths)-1] {
			if path.remote {
				return nil, nil, fmt.Errorf("copying between remote paths is not supported; copy to your machine first")
			}
		}
	}
	target, err := resolveTunnelTarget(newClient, streams, forwardOpts, rootOpts, trustOpts, identifier)
	if err != nil {
		return nil, nil, err
	}
	resolved := make([]string, len(paths))
	for i, path := range paths {
		resolved[i] = path.path
		if path.remote {
			if path.user == "" {
				path.user = user
			}
			resolved[i] = path.user + "@" + target.host + ":" + path.path
		}
	}
	return target, resolved, nil
}

func runSCP(streams commandIO, rootOpts *rootOptions, tunnelOpts *tunnelOptions, target *tunnelTarget, port int, options, paths []string) (int, error) {
	argv, err := sshProxyOptions(rootOpts, tunnelOpts, target, port)
	if err != nil {
		return 0, err
	}
	argv = append(argv, options...)
	argv = append(argv, "-o", "ServerAliveInterval="+strconv.Itoa(int(sshServerAliveInterval/time.Second)), "--")
	argv = append(argv, paths...)
	return runSSHClient(streams, tunnelOpts, "scp", argv)
}
