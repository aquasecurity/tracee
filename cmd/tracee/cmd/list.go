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
	listCmd.AddCommand(listFilterableCmd)
	listCmd.AddCommand(listDepsCmd)
}

var listCmd = &cobra.Command{
	Use:     "list <subcommand>",
	Aliases: []string{"l"},
	Short:   "List traceable events, detectors, policies, filterability, or dependencies",
	Long: `List traceable events, detectors, policies, field filterability, or event dependencies.

Subcommands:
  events      List traceable events with optional filtering
  detectors   List available detectors
  policies    List policies from a directory
  filterable  Show which event fields filter in the kernel vs user space
  deps        Show an event's dependency graph

Use 'tracee list <subcommand> --help' for more information about a subcommand.`,
	DisableFlagsInUseLine: true,
}
