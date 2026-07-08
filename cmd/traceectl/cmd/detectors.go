package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	cmdcobra "github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

var detectorsCmd = &cobra.Command{
	Use:   "detectors",
	Short: "Manage tracee detectors",
}

func init() {
	rootCmd.AddCommand(detectorsCmd)

	detectorsCmd.AddCommand(listDetectorsCmd)
	listDetectorsCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	listDetectorsCmd.Flags().String(flags.FormatFlag, printer.TableFormat, "Specify the format (json or table).")
	listDetectorsCmd.Flags().StringSlice("id", nil, "Filter by detector ID (repeatable).")

	detectorsCmd.AddCommand(describeDetectorsCmd)
	describeDetectorsCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	describeDetectorsCmd.Flags().String(flags.FormatFlag, printer.TableFormat, "Specify the format (json or table).")
	describeDetectorsCmd.Flags().String("name", "", "Detector event name.")
	describeDetectorsCmd.Flags().String("id", "", "Detector ID.")
}

var listDetectorsCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered detectors from Tracee gRPC",
	Long: `Fetches detector catalog entries via GetDetectorsCatalog.

Examples:
  traceectl detectors list
  traceectl detectors list --server /var/run/tracee.sock
  traceectl detectors list --format json
  traceectl detectors list --id TRH-12345`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetListDetectors(cmd)
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

var describeDetectorsCmd = &cobra.Command{
	Use:   "describe [EVENT_NAME]",
	Short: "Describe a detector from Tracee gRPC",
	Long: `Fetches a detector catalog entry via GetDetectorsCatalog.

Examples:
  traceectl detectors describe anti_debugging
  traceectl detectors describe --name anti_debugging
  traceectl detectors describe --id TRH-12345
  traceectl detectors describe --format json anti_debugging`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdcobra.GetDescribeDetector(cmd)
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
