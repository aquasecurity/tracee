package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "traceectl [command]",
		Short: "traceectl is a CLI tool for tracee",
		Long: `traceectl is a CLI tool for tracee:
This tool allows you to manage events, stream events directly from tracee, and get info about tracee.
`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func init() {
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
