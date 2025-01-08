package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
)

var (
	formatFlag string
	outputFlag string
	server     client.ServerInfo = client.ServerInfo{
		ConnectionType: client.Protocol_UNIX,
		Addr:           client.Socket,
	}
)

var (
	rootCmd = &cobra.Command{
		Use:   "traceectl [flags] [command]",
		Short: "traceectl is a CLI tool for tracee",
		Long: `traceectl is a CLI tool for tracee:
This tool allows you to manage events, stream events directly from tracee, and get info about tracee.
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if err = flags.PrepareOutput(cmd, outputFlag); err != nil {
				return err
			}
			if server, err = flags.PrepareServer(cmd, server); err != nil {
				return err
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func init() {
	rootCmd.AddCommand(streamCmd)
	rootCmd.AddCommand(eventCmd)
	rootCmd.AddCommand(metricsCmd)
	rootCmd.AddCommand(versionCmd)

	rootCmd.PersistentFlags().StringVar(&server.Addr, "server", client.Socket, `Server connection path or address.
	for unix socket <socket_path> (default: /tmp/tracee.sock)
	for tcp <IP:Port>`)
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "", "Specify the output format")
}

var metricsCmd = &cobra.Command{
	Use:   "metrics [--output <format>]",
	Short: "Display Tracee metrics",
	Long:  "Retrieves metrics about Tracee's performance and resource usage.",
	Run: func(cmd *cobra.Command, args []string) {
		displayMetrics(cmd, args)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version of tracee",
	Long:  "This is the version of the tracee application you connected to",
	Run: func(cmd *cobra.Command, args []string) {
		displayVersion(cmd, args)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func displayMetrics(cmd *cobra.Command, _ []string) {
	traceeClient, err := client.NewDiagnosticClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetMetrics(context.Background(), &pb.GetMetricsRequest{})
	if err != nil {
		cmd.PrintErrln("Error getting metrics: ", err)
		return
	}

	fmt.Fprintf(cmd.OutOrStdout(), "EventCount: %d\n", response.EventCount)
	fmt.Fprintf(cmd.OutOrStdout(), "EventsFiltered: %d\n", response.EventsFiltered)
	fmt.Fprintf(cmd.OutOrStdout(), "NetCapCount: %d\n", response.NetCapCount)
	fmt.Fprintf(cmd.OutOrStdout(), "BPFLogsCount: %d\n", response.BPFLogsCount)
	fmt.Fprintf(cmd.OutOrStdout(), "ErrorCount: %d\n", response.ErrorCount)
	fmt.Fprintf(cmd.OutOrStdout(), "LostEvCount: %d\n", response.LostEvCount)
	fmt.Fprintf(cmd.OutOrStdout(), "LostWrCount: %d\n", response.LostWrCount)
	fmt.Fprintf(cmd.OutOrStdout(), "LostNtCapCount: %d\n", response.LostNtCapCount)
	fmt.Fprintf(cmd.OutOrStdout(), "LostBPFLogsCount: %d\n", response.LostBPFLogsCount)
}

func displayVersion(cmd *cobra.Command, _ []string) {
	traceeClient, err := client.NewServiceClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetVersion(context.Background(), &pb.GetVersionRequest{})

	if err != nil {
		cmd.PrintErrln("Error getting version: ", err)
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Version: %s\n", response.Version)
}
