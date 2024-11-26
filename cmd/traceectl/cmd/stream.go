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
	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		stream(cmd, args)
	},
}

func init() {

	streamCmd.Flags().StringVarP(&streamFormatFlag, "format", "f", formatter.FormatJSON, "Output format (json|table|template)")
	streamCmd.Flags().StringVarP(&streamOutputFlag, "output", "o", "stdout", "Output destination ")
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
