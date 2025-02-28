package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	cmdcobra "github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

var eventCmd = &cobra.Command{
	Use:   "event [enable | disable | describe]",
	Short: "Manage tracee events",
	Long: `Manage events in tracee.


	Examples:
	  tracee event enable security_file_open
	  tracee event describe magic_write
	  tracee event list
	`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(eventCmd)
	//
	// describe Event
	//
	eventCmd.AddCommand(describeEventCmd)

	describeEventCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, describeEventCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}

	describeEventCmd.Flags().String(flags.FormatFlag, printer.TableFormat, "Specify the format (json or table).")
	if err := viper.BindPFlag(flags.FormatFlag, describeEventCmd.Flags().Lookup(flags.FormatFlag)); err != nil {
		panic(err)
	}
	describeEventCmd.Flags().String(flags.OutputFlag, "stdout", "Specify the output destination.")
	if err := viper.BindPFlag(flags.OutputFlag, describeEventCmd.Flags().Lookup(flags.OutputFlag)); err != nil {
		panic(err)
	}

	//
	// Enable Event
	//
	eventCmd.AddCommand(enableEventCmd)

	enableEventCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, enableEventCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}

	enableEventCmd.Flags().String(flags.OutputFlag, "stdout", "Specify the output destination.")
	if err := viper.BindPFlag(flags.OutputFlag, enableEventCmd.Flags().Lookup(flags.OutputFlag)); err != nil {
		panic(err)
	}

	//
	// Disable Event
	//
	eventCmd.AddCommand(disableEventCmd)

	disableEventCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, disableEventCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}

	disableEventCmd.Flags().String(flags.OutputFlag, "stdout", "Specify the output destination.")
	if err := viper.BindPFlag(flags.OutputFlag, disableEventCmd.Flags().Lookup(flags.OutputFlag)); err != nil {
		panic(err)
	}
}

var describeEventCmd = &cobra.Command{
	Use:   "describe <event name>",
	Short: "List available events",
	Long:  `Lists all available event definitions (built-in and plugin-defined), providing a brief summary of each.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetDescribeEvent(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}

		if err := runner.Run(args); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
	},
}

var enableEventCmd = &cobra.Command{
	Use:   "enable <event_name>",
	Short: "Enable an event",
	Long:  `Enables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetEnableEvent(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}

		if err := runner.Run(args); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
	},
}

var disableEventCmd = &cobra.Command{
	Use:   "disable <event_name>",
	Short: "Disable an event",
	Long:  `Disables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetDisableEvent(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}

		if err := runner.Run(args); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
	},
}
