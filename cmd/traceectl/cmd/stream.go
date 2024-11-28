package cmd

import (
	"fmt"
	"strings"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/formatter"
	"github.com/spf13/cobra"
)

var streamFormatFlag string
var streamCmd = &cobra.Command{
	Use:   "stream [policies...]",
	Short: "Stream events from tracee",
	Long: `Stream Management:
	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		streamEvents(cmd, args)
	},
}

func init() {
	streamCmd.Flags().StringVarP(&streamFormatFlag, "format", "f", formatter.FormatJson, "Output format (json|table)")

}

func streamEvents(cmd *cobra.Command, args []string) {
	//connect to tracee
	var traceeClient client.ServiceClient
	err := traceeClient.NewServiceClient(serverInfo)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()
	//request to stream events
	req := &pb.StreamEventsRequest{Policies: args}
	stream, err := traceeClient.StreamEvents(cmd.Context(), req)
	if err != nil {
		cmd.PrintErrln("Error calling Stream: ", err)
		return
	}
	//create formatter
	format, err := formatter.NewFormatter(streamFormatFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	switch format.GetFormat() {
	case formatter.FormatJson:
		//jsonStreamEvents(args, stream, format)
	case formatter.FormatTable:
		format.PrintTableHeaders([]string{"TIME", "EVENT NAME", "POLICIES", "PID", "DATA"})
		for {
			res, err := stream.Recv()
			if err != nil {
				//End of stream\close connection
				if err.Error() == "EOF" {
					break
				}
				//Error receiving streamed event
			}

			format.PrintTableRow(prepareEvent(res.Event))
		}
	default:
		//Error: output format not supported
		return
	}
}
func prepareEvent(event *pb.Event) []string {
	return []string{
		event.Timestamp.AsTime().Format("15:04:05.000"),
		event.Name,
		strings.Join(event.Policies.Matched, ","),
		fmt.Sprintf("%d", event.Context.Process.Pid.Value),
		getEventData(event.Data),
	}

}
func getEventData(data []*pb.EventValue) string {
	var result []string
	for _, ev := range data {
		result = append(result, getEventName(ev)+getEventValue(ev))
	}
	return strings.Join(result, ", ")
}
func getEventName(ev *pb.EventValue) string {
	return strings.ToUpper(ev.Name[0:1]) + ev.Name[1:] + ": "
}
func getEventValue(ev *pb.EventValue) string {
	switch v := ev.Value.(type) {
	case *pb.EventValue_Int32:
		return fmt.Sprintf("%d", v.Int32)
	case *pb.EventValue_Int64:
		return fmt.Sprintf("%d", v.Int64)
	case *pb.EventValue_UInt32:
		return fmt.Sprintf("%d", v.UInt32)
	case *pb.EventValue_UInt64:
		return fmt.Sprintf("%d", v.UInt64)
	case *pb.EventValue_Str:
		return v.Str
	case *pb.EventValue_Bytes:
		return fmt.Sprintf("%x", v.Bytes)
	case *pb.EventValue_Bool:
		return fmt.Sprintf("%t", v.Bool)
	case *pb.EventValue_StrArray:
		return strings.Join(v.StrArray.Value, ", ")
	case *pb.EventValue_Int32Array:
		return fmt.Sprintf("%v", v.Int32Array.Value)
	case *pb.EventValue_UInt64Array:
		return fmt.Sprintf("%v", v.UInt64Array.Value)
	default:
		return "unknown"
	}
}
