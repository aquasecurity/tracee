package cmd

import (
	"github.com/spf13/cobra"

	tcmd "github.com/aquasecurity/tracee/pkg/cmd"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "List traceable events",
	Long:    ``,
	Run: func(cmd *cobra.Command, args []string) {
		tcmd.PrintEventList(true) // list events
	},
	DisableFlagsInUseLine: true,
}
