package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func init() {
	// override the default help command
	rootCmd.SetHelpCommand(helpCmd)
	// use custom usage template
	rootCmd.SetUsageTemplate(customUsageTemplate)
}

var customUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use:
  "{{.CommandPath}} [command] --help" for more information about a command.
  "{{.CommandPath}} help [command|flag]" for more information about a command or flag.{{end}}
`

var helpCmd = &cobra.Command{
	Use:    "help [command|flag]",
	Short:  "Help about any command or flag",
	Hidden: false,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			// check if the argument is a flag
			if flagHelp := flags.GetHelpString(args[0], true); flagHelp != "" {
				fmt.Fprintf(os.Stdout, "%s\n", flagHelp)
				return
			}

			// check if the argument is a command
			for _, cmd := range rootCmd.Commands() {
				if cmd.Name() == args[0] {
					if err := cmd.Help(); err != nil {
						logger.Errorw("failed to print help for command", "command", cmd.Name(), "error", err)
						os.Exit(1)
					}
					return
				}
			}
		}

		// use the default help function
		cmd.Root().HelpFunc()(cmd.Root(), args)
	},
}
