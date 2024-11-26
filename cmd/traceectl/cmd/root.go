package cmd

import (
	"context"
	"os"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"

	"github.com/spf13/cobra"
)

var formatFlag string
var outputFlag string
var serverFlag string
var (
	serverInfo client.ServerInfo = client.ServerInfo{
		ConnectionType: client.PROTOCOL_UNIX,
		ADDR:           client.SOCKET,
	}

	rootCmd = &cobra.Command{
		Use:   "traceectl [flags] [command]",
		Short: "TraceeCtl is a CLI tool for tracee",
		Long:  "TraceeCtl is the client for the tracee API server.",
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

	rootCmd.PersistentFlags().StringVar(&serverInfo.ADDR, "server", client.SOCKET, `Server connection path or address.
	for unix socket <socket_path> (default: /tmp/tracee.sock)
	for tcp <IP:Port>`)

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
	if err := traceeClient.NewDiagnosticClient(serverInfo); err != nil {
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
	if err := traceeClient.NewServiceClient(serverInfo); err != nil {
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
