package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listCmd)

	// Add subcommands
	listCmd.AddCommand(listEventsCmd)
	listCmd.AddCommand(listDetectorsCmd)
	listCmd.AddCommand(listPoliciesCmd)
}

var listCmd = &cobra.Command{
	Use:     "list <subcommand>",
	Aliases: []string{"l"},
	Short:   "List traceable events, detectors, or policies",
	Long: `List traceable events, detectors, or policies.

Subcommands:
  events     List traceable events with optional filtering
  detectors  List available detectors
  policies   List policies from a directory

Use 'tracee list <subcommand> --help' for more information about a subcommand.`,
	DisableFlagsInUseLine: true,
}
