package main

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	{"sandboxes", color.FgMagenta, []string{"monitor", "sandbox"}},
	{"connect", color.FgBlue, []string{"attest-ssh", "forward", "http", "scp", "ssh"}},
	{"verify", color.FgGreen, []string{"attestation", "trust"}},
	{"account", color.FgYellow, []string{"login", "logout", "whoami"}},
	{cliGroup, color.FgWhite, []string{"update"}},
}

// Subcommands inherit their nearest mapped parent's page; "" means none is published.
var docsPages = map[string]string{
	"tinfoil":                    "sdk/cli-sdk",
	"tinfoil attest-ssh":         "containers/attested-ssh",
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
	"tinfoil monitor":            "",
	"tinfoil project":            "containers/projects",
	"tinfoil project storage":    "containers/volume-auto-unlock",
	"tinfoil project update":     "containers/updates",
	"tinfoil registry":           "containers/private-images",
	"tinfoil repo":               "containers/cli",
	"tinfoil repo secret":        "containers/secrets-and-env-vars",
	"tinfoil sandbox":            "",
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

var (
	enclaveHost, repo string
	localConfigFile   string
	verbose, trace    bool
	version           = defaultVersion
	// exitCode is the status a command wants the process to end with, for the
	// ones that stand in for another program.
	exitCode int
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tinfoil",
		Short:   "Verify, connect to, and manage Tinfoil enclaves",
		Version: version,
	}
	cmd.PersistentFlags().StringVar(&localConfigFile, "config", "", "Local config file to launch or trust for verification")
	return cmd
}

var rootCmd = newRootCommand()

func init() {
	rootCmd.PersistentFlags().StringVarP(&enclaveHost, "enclave", "e", "", "Enclave hostname (for example inference.tinfoil.sh)")
	rootCmd.PersistentFlags().StringVarP(&repo, "repo", "r", "", "Expected config source: owner/name[@tag][@sha256:digest]")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "t", false, "Trace output")
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Show help")
	_ = rootCmd.PersistentFlags().MarkHidden("help")

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

func main() {
	if trace {
		log.SetLevel(log.TraceLevel)
	} else if verbose {
		log.SetLevel(log.InfoLevel)
	}

	waitForUpdateCheck := func() (string, bool) { return "", false }
	if !isSelfUpdateCommand(rootCmd, os.Args[1:]) {
		waitForUpdateCheck = startUpdateCheck()
	}

	for _, g := range commandGroups {
		rootCmd.AddGroup(&cobra.Group{ID: g.id})
		for _, cmd := range rootCmd.Commands() {
			if slices.Contains(g.commands, cmd.Name()) {
				cmd.GroupID = g.id
			}
		}
	}
	rootCmd.SetHelpCommandGroupID(cliGroup)
	rootCmd.SetCompletionCommandGroupID(cliGroup)

	err := rootCmd.Execute()
	if hint := errorHint(err); hint != "" {
		fmt.Fprintln(os.Stderr, hint)
	}

	if latest, ok := waitForUpdateCheck(); ok {
		printUpdateNotice(latest)
	}

	if err != nil {
		exitCode = 1
	}
	os.Exit(exitCode)
}
