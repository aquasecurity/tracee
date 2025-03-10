package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	cmdcobra "github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Display Tracee metrics",
	Long:  "Retrieves metrics about Tracee's performance and resource usage.",
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetMetrics(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}
		if err := runner.Run(); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
		runner.Server.Close()
	},
}

func init() {
	rootCmd.AddCommand(metricsCmd)

	metricsCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, metricsCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}
}
