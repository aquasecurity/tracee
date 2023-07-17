package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"v"},
	Short:   "Print the version number of Tracee",
	Long:    ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Tracee version: %s\n", version.GetVersion())
	},
	DisableFlagsInUseLine: true,
}
