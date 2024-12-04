package cmd

import (
	"context"
	"os"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"

	"github.com/spf13/cobra"
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
		Short: "TraceeCtl is a CLI tool for tracee",
		Long: `TraceeCtl is a CLI toll for tracee:
This tool allows you to mange event, stream events directly from tracee, and get info about tracee.
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
	Long:  "This is the version of tracee application you connected to",
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
	var traceeClient client.DiagnosticClient
	if err := traceeClient.NewDiagnosticClient(server); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetMetrics(context.Background(), &pb.GetMetricsRequest{})
	if err != nil {
		cmd.PrintErrln("Error getting metrics: ", err)
		return
	}
	cmd.Println("EventCount:", response.EventCount)
	cmd.Println("EventsFiltered:", response.EventsFiltered)
	cmd.Println("NetCapCount:", response.NetCapCount)
	cmd.Println("BPFLogsCount:", response.BPFLogsCount)
	cmd.Println("ErrorCount:", response.ErrorCount)
	cmd.Println("LostEvCount:", response.LostEvCount)
	cmd.Println("LostWrCount:", response.LostWrCount)
	cmd.Println("LostNtCapCount:", response.LostNtCapCount)
	cmd.Println("LostBPFLogsCount:", response.LostBPFLogsCount)
}

func displayVersion(cmd *cobra.Command, _ []string) {
	var traceeClient client.ServiceClient
	if err := traceeClient.NewServiceClient(server); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetVersion(context.Background(), &pb.GetVersionRequest{})

	if err != nil {
		cmd.PrintErrln("Error getting version: ", err)
		return
	} else {
		cmd.Println("Version: ", response.Version)
	}
}
