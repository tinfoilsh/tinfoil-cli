package main

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	defaultVersion = "dev"
	cliGroup       = "cli"
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

var flagSpec = regexp.MustCompile(`(?m)^( +)(-.*?)( [^- ]\S*)?( {2,}|$)`)

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
		return flagSpec.ReplaceAllString(s, "${1}"+literal("${2}")+placeholder("${3}")+"${4}")
	})
	tpl := strings.NewReplacer(
		"{{.UseLine}}", "{{literal .UseLine}}",
		"  {{.CommandPath}} [command]", "  {{literal .CommandPath}} [command]",
		"{{rpad .Name .NamePadding }}", "{{command .}}",
		"| trimTrailingWhitespaces}}", "| trimTrailingWhitespaces | flags}}",
		"{{range $group := .Groups}}\n\n{{.Title}}", "\n\nAvailable Commands:{{range $i, $group := .Groups}}{{if $i}}\n{{end}}",
	).Replace(rootCmd.UsageTemplate())
	rootCmd.SetUsageTemplate(regexp.MustCompile(`(?m)^([A-Z][\w ]+:)`).ReplaceAllString(tpl, `{{heading "$1"}}`))
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
