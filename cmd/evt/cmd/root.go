package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/evt/cmd/stress"
	"github.com/aquasecurity/tracee/cmd/evt/cmd/trigger"
)

func init() {
	rootCmd.AddCommand(stress.Cmd())
	rootCmd.AddCommand(trigger.Cmd())
}

var (
	rootCmd = &cobra.Command{
		Use:   "evt",
		Short: "An event stress testing tool",
		Long:  "evt is a simple testing tool that generates events to stress the system",
	}
)

func initRootCmd() error {
	rootCmd.SetOutput(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	return nil
}

func Execute() error {
	if err := initRootCmd(); err != nil {
		return err
	}

	return rootCmd.Execute()
}
