package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
)

const (
	defaultVersion = "dev"
	cliGroup       = "cli"
	docsBase       = "https://docs.tinfoil.sh/"
)

var commandGroups = []struct {
	id       string
	color    color.Attribute
	commands []string
}{
	{"containers", color.FgCyan, []string{"container", "domain", "model", "project", "registry", "repo", "secret", "ssh-key", "volume"}},
	{"sandboxes", color.FgMagenta, []string{"bunker", "perimeter"}},
	{"connect", color.FgBlue, []string{"attest-ssh", "forward", "http", "scp", "ssh"}},
	{"verify", color.FgGreen, []string{"attestation", "trust"}},
	{"account", color.FgYellow, []string{"login", "logout", "whoami"}},
	{cliGroup, color.FgWhite, []string{"update"}},
}

// Subcommands inherit their nearest mapped parent's page; "" means none is published.
var docsPages = map[string]string{
	"tinfoil":                    "sdk/cli-sdk",
	"tinfoil attest-ssh":         "containers/attested-ssh",
	"tinfoil bunker":             "",
	"tinfoil container":          "containers/cli",
	"tinfoil container cancel":   "containers/updates",
	"tinfoil container connect":  "containers/connecting",
	"tinfoil container promote":  "containers/hold-for-review",
	"tinfoil container update":   "containers/updates",
	"tinfoil domain":             "containers/custom-domains",
	"tinfoil forward":            "containers/connecting",
	"tinfoil login":              "containers/cli",
	"tinfoil logout":             "containers/cli",
	"tinfoil model":              "containers/models",
	"tinfoil perimeter":          "",
	"tinfoil project":            "containers/projects",
	"tinfoil project storage":    "containers/volume-auto-unlock",
	"tinfoil project update":     "containers/updates",
	"tinfoil registry":           "containers/private-images",
	"tinfoil repo":               "containers/cli",
	"tinfoil repo secret":        "containers/secrets-and-env-vars",
	"tinfoil scp":                "containers/connecting",
	"tinfoil secret":             "containers/secrets-and-env-vars",
	"tinfoil ssh":                "containers/connecting",
	"tinfoil ssh-key":            "containers/cli",
	"tinfoil volume":             "containers/encrypted-volumes",
	"tinfoil volume auto-unlock": "containers/volume-auto-unlock",
	"tinfoil whoami":             "containers/cli",
}

var (
	flagSpec       = regexp.MustCompile(`(?m)^( +)(-.*?)( [^- ]\S*)?( {2,}|$)`)
	exampleCommand = regexp.MustCompile(`(?m)^( *)(tinfoil\b.*)$`)
)

func newRootCommandWithDependencies(dependencies commandDependencies) *cobra.Command {
	pollingOpts := defaultPollingOptions()
	if dependencies.polling != nil {
		*pollingOpts = *dependencies.polling
	}
	rootOpts := &rootOptions{connections: connectionDependencies{
		proxyClient: dependencies.proxyClient, serveProxy: dependencies.serveProxy,
		verifySandboxEvidence: dependencies.verifySandboxEvidence,
	}}
	commandVersion := dependencies.version
	if commandVersion == "" {
		commandVersion = defaultVersion
	}
	settings := defaultAuthSettings()
	if dependencies.authSettings != nil {
		settings = *dependencies.authSettings
	}
	credentials := dependencies.credentials
	if credentials == nil {
		credentials = func() (*auth.Store, error) { return credentialStore(auth.OSKeyring{}) }
	}
	accounts := newAccountAccess(settings, commandVersion, credentials, dependencies.accountHTTP)
	volumeStore := dependencies.volumeStore
	if volumeStore == nil {
		volumeStore = autounlock.NewAWSKeyStore
	}

	cmd := &cobra.Command{
		Use:          "tinfoil",
		Short:        "Verify, connect to, and manage Tinfoil enclaves",
		Version:      commandVersion,
		SilenceUsage: true,
	}
	cmd.SetIn(dependencies.in)
	// Cobra prints diagnostics such as unknown help topics through
	// OutOrStderr, which reaches stderr only while no output writer is set.
	if dependencies.out != os.Stdout {
		cmd.SetOut(dependencies.out)
	}
	cmd.SetErr(dependencies.err)
	rootOpts.registryOrigin = func() (string, error) { return accounts.registryControlplaneURL(commandStreams(cmd)) }
	cmd.PersistentFlags().StringVar(&rootOpts.localConfigFile, "config", "", "Local config file to launch or trust for verification")
	cmd.PersistentFlags().BoolVar(&rootOpts.publicRegistry, "public-registry", false, "Require public configs, even when a private registry is trusted")
	cmd.MarkFlagsMutuallyExclusive("config", "public-registry")
	configureRootCommand(rootOpts, cmd)
	cmd.AddCommand(newAttestSSHCommand(accounts.authedClient, accounts.currentScope, &attestSSHOptions{}, &forwardOptions{}, &identityOptions{}, rootOpts, &trustOptions{}), newAttestationCommand(rootOpts), newLoginCommand(accounts, dependencies.browser()), newLogoutCommand(accounts), newWhoamiCommand(accounts),
		newContainerCommand(pollingOpts, accounts.authedClient, &outputOptions{}, rootOpts), newDomainCommand(accounts.authedClient, &outputOptions{}), newHttpCommand(&headersOptions{}, rootOpts), newModelCommand(pollingOpts, accounts.authedClient, &outputOptions{}), newProjectCommand(accounts.authedClient, &outputOptions{}), newProxyCommand(&proxyOptions{}, rootOpts),
		newRegistryCommand(accounts.authedClient, &outputOptions{}), newRepoCommand(accounts.authedClient, &outputOptions{}), newSCPCommand(accounts.authedClient, &forwardOptions{}, rootOpts, &trustOptions{}, &tunnelOptions{}), newSecretCommand(accounts.authedClient, &outputOptions{}), newSshCommand(accounts.authedClient, &forwardOptions{}, rootOpts, &sshOptions{}, &trustOptions{}, &tunnelOptions{}), newSshKeyCommand(accounts.authedClient, &outputOptions{}, &sshKeyOptions{}),
		newTrustCommand(accounts, &trustOptions{}), newForwardCommand(accounts.authedClient, &forwardOptions{}, rootOpts, &trustOptions{}, &tunnelOptions{}), newVolumeCommand(accounts.authedClient, volumeStore, &outputOptions{}), newSelfUpdateCommand(func() selfUpdateRunner {
			return newDefaultSelfUpdater(commandVersion, dependencies.updateTransport)
		}))
	monitorIdentity, sandboxIdentity := &identityOptions{}, &identityOptions{}
	monitorOutput, sandboxOutput := &outputOptions{}, &outputOptions{}
	monitor, sandbox := newMonitorCommand(), newSandboxCommand(pollingOpts, accounts.authedClient, accounts.currentScope, sandboxIdentity, sandboxOutput, rootOpts)
	monitor.AddCommand(newMonitorOpenCommand(accounts.currentScope, monitorIdentity, rootOpts, &trustOptions{}, dependencies.browser()))
	monitor.AddCommand(newManagedStatusCmd(pollingOpts, accounts.authedClient, monitorOutput, "monitor"))
	addManagedCommands(pollingOpts, accounts.authedClient, accounts.currentScope, monitorIdentity, monitorOutput, monitor, "monitor")
	addManagedCommands(pollingOpts, accounts.authedClient, accounts.currentScope, sandboxIdentity, sandboxOutput, sandbox, "sandbox")
	cmd.AddCommand(monitor, sandbox)
	create, _, _ := cmd.Find([]string{"container", "create"})
	create.MarkFlagsMutuallyExclusive("config", "repo")
	create.MarkFlagsMutuallyExclusive("config", "tag", "revision")
	create.MarkFlagsOneRequired("config", "tag", "revision")
	for _, g := range commandGroups {
		cmd.AddGroup(&cobra.Group{ID: g.id})
		for _, child := range cmd.Commands() {
			if slices.Contains(g.commands, child.Name()) {
				child.GroupID = g.id
			}
		}
	}
	cmd.SetHelpCommandGroupID(cliGroup)
	cmd.SetCompletionCommandGroupID(cliGroup)
	return cmd
}

var helpTemplatesOnce sync.Once

func configureRootCommand(rootOpts *rootOptions, rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().StringVarP(&rootOpts.enclaveHost, "enclave", "e", "", "Enclave hostname (for example inference.tinfoil.sh)")
	rootCmd.PersistentFlags().StringVarP(&rootOpts.repo, "repo", "r", "", "Expected config source: owner/name[@tag][@sha256:digest]")
	rootCmd.PersistentFlags().BoolVarP(&rootOpts.verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&rootOpts.trace, "trace", "t", false, "Trace output")
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Show help")
	_ = rootCmd.PersistentFlags().MarkHidden("help")

	helpTemplatesOnce.Do(registerHelpTemplates)
	configureHelpTemplates(rootCmd)
}

func registerHelpTemplates() {
	literal := color.New(color.FgCyan, color.Bold).SprintFunc()
	placeholder := color.New(color.FgCyan).SprintFunc()
	cobra.AddTemplateFunc("heading", color.New(color.FgGreen, color.Bold).SprintFunc())
	cobra.AddTemplateFunc("literal", literal)
	cobra.AddTemplateFunc("command", func(c *cobra.Command) string {
		fg := color.FgCyan
		for _, g := range commandGroups {
			if g.id == c.GroupID {
				fg = g.color
			}
		}
		return color.New(fg, color.Bold).Sprintf("%-*s", c.NamePadding(), c.Name())
	})
	cobra.AddTemplateFunc("flags", func(s string) string {
		var b strings.Builder
		w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
		fmt.Fprint(w, flagSpec.ReplaceAllStringFunc(s, func(line string) string {
			m := flagSpec.FindStringSubmatch(line)
			value := ""
			if strings.Contains(m[3], "[=") {
				value = "[=<val>]"
			} else if m[3] != "" {
				value = "=<val>"
			}
			return m[1] + literal(m[2]) + placeholder(value) + "\t"
		}))
		_ = w.Flush()
		return b.String()
	})
	cobra.AddTemplateFunc("examples", func(s string) string {
		return exampleCommand.ReplaceAllString(s, "${1}"+literal("${2}"))
	})
	cobra.AddTemplateFunc("docs", func(c *cobra.Command) string {
		for ; c != nil; c = c.Parent() {
			if page, ok := docsPages[c.CommandPath()]; ok {
				return page
			}
		}
		return ""
	})
	cobra.AddTemplateFunc("inherited", func(c *cobra.Command) string {
		fs := pflag.NewFlagSet(c.Name(), pflag.ContinueOnError)
		c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
			if c.Root().PersistentFlags().Lookup(f.Name) == nil {
				fs.AddFlag(f)
			}
		})
		return fs.FlagUsages()
	})
}

func configureHelpTemplates(rootCmd *cobra.Command) {
	tpl := strings.NewReplacer(
		"{{.UseLine}}", "{{literal .UseLine}}",
		"  {{.CommandPath}} [command]", "  {{literal .CommandPath}} [command]",
		"{{rpad .Name .NamePadding }}", "{{command .}}",
		"| trimTrailingWhitespaces}}", "| trimTrailingWhitespaces | flags}}",
		"{{range $group := .Groups}}\n\n{{.Title}}", "\n\nAvailable Commands:{{range $i, $group := .Groups}}{{if $i}}\n{{end}}",
		"{{if .HasExample}}\n\nExamples:\n{{.Example}}{{end}}", "",
		"{{if .HasAvailableInheritedFlags}}\n\nGlobal Flags:\n{{.InheritedFlags.FlagUsages", "{{with inherited .}}\n\nInherited Flags:\n{{.",
		"{{if .HasHelpSubCommands}}", "{{if .HasExample}}\n\nExamples:\n{{examples .Example}}{{end}}{{if .HasHelpSubCommands}}",
		"{{if .HasAvailableSubCommands}}\n\nUse", "\n{{if .HasAvailableSubCommands}}\nUse",
		"for more information about a command.{{end}}", "for more information about a command.{{end}}{{if .HasParent}}\nUse \"{{.Root.Name}} --help\" for global flags.{{end}}{{with docs .}}\nDocs: "+docsBase+"{{.}}{{end}}",
	).Replace(rootCmd.UsageTemplate())
	rootCmd.SetUsageTemplate(regexp.MustCompile(`(?m)^([A-Z][\w ]+:)`).ReplaceAllString(tpl, `{{heading "$1"}}`))
	rootCmd.SetHelpTemplate(strings.Replace(rootCmd.HelpTemplate(), "{{with (or .Long .Short)}}", "{{with .Short}}{{.}}\n\n{{end}}{{with .Long}}", 1))
}

func run(args []string, dependencies commandDependencies) int {
	rootCmd := newRootCommandWithDependencies(dependencies)
	return runCommand(rootCmd, args, dependencies.updateTransport)
}

func runCommand(rootCmd *cobra.Command, args []string, updateTransport http.RoundTripper) int {
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	rootCmd.SetArgs(args)
	waitForUpdateCheck := func() (string, bool) { return "", false }
	if !isSelfUpdateCommand(rootCmd, args) {
		waitForUpdateCheck = startUpdateCheck(commandStreams(rootCmd), rootCmd.Version, updateTransport)
	}

	err := executeCommand(rootCmd, args)
	var exited *processExit
	if err != nil && !errors.As(err, &exited) {
		fmt.Fprintln(rootCmd.ErrOrStderr(), "Error:", err)
		if command, _, lookupErr := rootCmd.Find(args); lookupErr != nil {
			fmt.Fprintf(rootCmd.ErrOrStderr(), "Run '%s --help' for usage.\n", command.CommandPath())
		}
	}
	if hint := errorHint(err); hint != "" {
		fmt.Fprintln(rootCmd.ErrOrStderr(), hint)
	}

	if latest, ok := waitForUpdateCheck(); ok {
		printUpdateNotice(commandStreams(rootCmd), rootCmd.Version, latest)
	}

	if err != nil {
		if exited != nil {
			return exited.code
		}
		return 1
	}
	return 0
}

func executeCommand(root *cobra.Command, args []string) error {
	command, _, err := root.Find(args)
	if err == nil && command.Deprecated != "" {
		// Cobra sends deprecation notices to its output writer; these are diagnostics.
		message := command.Deprecated
		fmt.Fprintf(command.ErrOrStderr(), "Command %q is deprecated, %s\n", command.Name(), message)
		command.Deprecated = ""
		defer func() { command.Deprecated = message }()
	}
	return root.Execute()
}
