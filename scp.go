package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(newSCPCommand())
}

func newSCPCommand() *cobra.Command {
	var user string
	var port uint
	cmd := &cobra.Command{
		Use:   "scp <source>... <destination> [-- scp options...]",
		Short: "Copy files through the verified enclave tunnel",
		Long: `Copy files between your machine and a container over the enclave's
attested TLS connection, using your local scp and the same tunnel as tinfoil ssh.

Use [user@]container:path or [user@]hostname:path for remote files. The target
and SSH port are resolved just as for tinfoil ssh. The default user is root;
-l changes it, and an explicit user@ in a path takes precedence. Use :path
with --host to select the remote enclave separately.

The container must publish its SSH port in tinfoil-config.yml. Transfers may
use multiple sources, but must be between your machine and one enclave.

Put native scp options after --. As with tinfoil ssh, -p before -- sets the
enclave-side port; scp's -p after -- preserves file times and permissions.

  tinfoil scp ./file.txt my-container:/tmp/
  tinfoil scp my-container:/var/log/app.log ./app.log
  tinfoil scp ./data my-container:/data -- -r
  tinfoil scp ./file.txt ubuntu@enclave.example.com:/tmp/ -p 2022
  tinfoil scp --host enclave.example.com ./file.txt :/tmp/`,
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
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
			target, paths, err := resolveSCPPaths(args, user)
			if err != nil {
				return err
			}
			return sshExit(runSCP(target, sshTargetPort(target, port), options, paths))
		},
	}
	cmd.Flags().StringVarP(&user, "user", "l", "root", "Remote user to log in as")
	cmd.Flags().UintVarP(&port, "port", "p", 0, "Enclave-side SSH port (default: the container's published SSH port, else 22)")
	addTunnelFlags(cmd)
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

func resolveSCPPaths(args []string, user string) (*tunnelTarget, []string, error) {
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
			path.identifier = enclaveHost
		}
		if path.identifier == "" {
			return nil, nil, fmt.Errorf("name a container or hostname before ':', or pass --host")
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
	target, err := resolveTunnelTarget(identifier)
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

func runSCP(target *tunnelTarget, port int, options, paths []string) (int, error) {
	argv, err := sshProxyOptions(target, port)
	if err != nil {
		return 0, err
	}
	argv = append(argv, options...)
	argv = append(argv, "-o", "ServerAliveInterval="+strconv.Itoa(int(sshServerAliveInterval/time.Second)), "--")
	argv = append(argv, paths...)
	return runSSHClient("scp", argv)
}
