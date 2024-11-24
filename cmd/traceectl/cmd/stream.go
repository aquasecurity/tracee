package cmd

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/formatter"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"

	"github.com/spf13/cobra"
)

var streamFormatFlag string
var streamOutputFlag string
var streamCmd = &cobra.Command{
	Use:   "stream [policies...]",
	Short: "Stream events from tracee",
	Long: `Stream Management:
	- traceectl stream [POLICIES...] -  stream event directly from tracee
  	- traceectl stream create --name <stream_name> [--destination <destination>] [--format <format>] [--fields <fields>] [--parse-data] [--filter <filter>]
  	- traceectl stream describe <stream_name>
  	- traceectl stream list
  	- traceectl stream update <stream_name> [--destination <destination>] [--format <format>] [--fields <fields>] [--parse-data] [--filter <filter>]
  	- traceectl stream delete <stream_name>
  	- traceectl stream connect <stream_name>
  	- traceectl stream set-default <stream_name>
  	- traceectl stream pause <stream_name>
  	- traceectl stream resume <stream_name>
	`,
	Run: func(cmd *cobra.Command, args []string) {
		stream(cmd, args)
	},
}

func init() {
	streamCmd.AddCommand(createStreamCmd)
	streamCmd.AddCommand(describeStreamCmd)
	streamCmd.AddCommand(listStreamCmd)
	streamCmd.AddCommand(updateStreamCmd)
	streamCmd.AddCommand(deleteStreamCmd)
	streamCmd.AddCommand(connectStreamCmd)
	streamCmd.AddCommand(setDefaultStreamCmd)
	streamCmd.AddCommand(pauseStreamCmd)
	streamCmd.AddCommand(resumeStreamCmd)
	streamCmd.Flags().StringVarP(&streamFormatFlag, "format", "f", formatter.FormatJSON, "Output format (json|table|template)")
	streamCmd.Flags().StringVarP(&streamOutputFlag, "output", "o", "stdout", "Output destination ")
}

var createStreamCmd = &cobra.Command{
	Use:   "create --name <stream_name> [--destination <destination>] [--format <format>] [--fields <fields>] [--parse-data] [--filter <filter>]",
	Short: "Create a new stream",
	Long:  `Creates a new event stream with a specified name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var describeStreamCmd = &cobra.Command{
	Use:   "describe <stream_name>",
	Short: "Describe a stream",
	Long:  `Retrieves the details of a specific stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var listStreamCmd = &cobra.Command{
	Use:   "list",
	Short: "List streams",
	Long:  `Lists all available streams, providing a brief summary of each.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var updateStreamCmd = &cobra.Command{
	Use:   "update <stream_name> [--destination <destination>] [--format <format>] [--fields <fields>] [--parse-data] [--filter <filter>]",
	Short: "Update a stream",
	Long:  `Updates a stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var deleteStreamCmd = &cobra.Command{
	Use:   "delete <stream_name>",
	Short: "Delete a stream",
	Long:  `Deletes a stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var connectStreamCmd = &cobra.Command{
	Use:   "connect <stream_name>",
	Short: "Connect a stream",
	Long:  `Connects a stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var setDefaultStreamCmd = &cobra.Command{
	Use:   "set-default <stream_name>",
	Short: "Set default stream",
	Long:  `Sets a stream as the default stream.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var pauseStreamCmd = &cobra.Command{
	Use:   "pause <stream_name>",
	Short: "Pause a stream",
	Long:  `Pauses a stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var resumeStreamCmd = &cobra.Command{
	Use:   "resume <stream_name>",
	Short: "Resume a stream",
	Long:  `Resumes a stream by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func stream(cmd *cobra.Command, args []string) {

	var traceeClient client.ServiceClient
	err := traceeClient.NewServiceClient(serverInfo)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()
	req := &pb.StreamEventsRequest{Policies: args}
	stream, err := traceeClient.StreamEvents(cmd.Context(), req)
	if err != nil {
		cmd.PrintErrln("Error calling Stream: ", err)
		return
	}
	format, err := formatter.New(streamFormatFlag, streamOutputFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	printer.StreamEvents(format, args, stream)

}
