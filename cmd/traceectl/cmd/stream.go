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

var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Stream events from tracee",
	Long: `Stream Management:
Stream events directly from tracee to the preferred output format.
`,
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetStream(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}

		if err := runner.Run(); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(streamCmd)

	streamCmd.Flags().String(flags.FormatFlag, printer.TableFormat, "Specify the format for streamed events (json or table).")
	if err := viper.BindPFlag(flags.FormatFlag, streamCmd.Flags().Lookup(flags.FormatFlag)); err != nil {
		panic(err)
	}
	streamCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, streamCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}
	streamCmd.Flags().String(flags.OutputFlag, "stdout", "Specify the output destination for streamed events.")
	if err := viper.BindPFlag(flags.OutputFlag, streamCmd.Flags().Lookup(flags.OutputFlag)); err != nil {
		panic(err)
	}
	streamCmd.Flags().StringSlice(flags.PolicyFlag, []string{""}, "Specify the policies for streamed events.")
	if err := viper.BindPFlag(flags.PolicyFlag, streamCmd.Flags().Lookup(flags.PolicyFlag)); err != nil {
		panic(err)
	}
}
