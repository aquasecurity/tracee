package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/evt/cmd/trigger"
)

func init() {
	rootCmd.AddCommand(trigger.Cmd())
}

var (
	rootCmd = &cobra.Command{
		Use:   "evt",
		Short: "An event generator for testing purposes",
		Long:  "evt is a simple testing tool that generates events to trace or to stress the system.",
	}
)

func initRootCmd() error {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	return nil
}

func Execute(ctx context.Context) error {
	if err := initRootCmd(); err != nil {
		return err
	}

	return rootCmd.ExecuteContext(ctx)
}
