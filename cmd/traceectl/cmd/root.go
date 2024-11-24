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
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(policyCmd)

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(metricsCmd)
	rootCmd.AddCommand(diagnoseCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)

	rootCmd.PersistentFlags().StringVar(&serverInfo.ADDR, "server", client.SOCKET, `Server connection path or address.
	for unix socket <socket_path> (default: /tmp/tracee.sock)
	for tcp <IP:Port>`)

}

var connectCmd = &cobra.Command{
	Use:   "connect [<stream_name>]",
	Short: "Connect to the server",
	Long:  "Connects to a stream and displays events in real time.",
	Run: func(cmd *cobra.Command, args []string) {
	},
}
var metricsCmd = &cobra.Command{
	Use:   "metrics [--output <format>]",
	Short: "Display Tracee metrics",
	Long:  "Retrieves metrics about Tracee's performance and resource usage.",
	Run: func(cmd *cobra.Command, args []string) {
		displayMetrics(cmd, args)
	},
}
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose [--component <component_name>]",
	Short: "Collect diagnostic information to help troubleshoot issues",
	Long:  "Collects diagnostic information to help troubleshoot issues.",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var logsCmd = &cobra.Command{
	Use:   "logs [--filter <filter>]",
	Short: "Display log messages from Tracee",
	Long:  "Displays log messages from Tracee, optionally filtered.",
	Run: func(cmd *cobra.Command, args []string) {
	},
}
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Shows the status of the Tracee Daemon and its components",
	Long:  "Shows the status of the Tracee Daemon and its components.",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var configCmd = &cobra.Command{
	Use:   "config [set|get|update] [<option>=<value>] [--file <config_file>]",
	Short: "View or modify the Tracee Daemon configuration at runtime.",
	Long:  `View or modify the Tracee Daemon configuration at runtime.`,
	Run: func(cmd *cobra.Command, args []string) {
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
