package printer

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/formatter"
)

func StreamEvents(format *formatter.Formatter, args []string, stream pb.TraceeService_StreamEventsClient) {

	//add check for the output flag
	//TODO:support only table and json format for now
	switch format.Format {
	case formatter.FormatJSON:
		jsonStreamEvents(args, stream, format)
	case formatter.FormatTable:
		tableStreamEvents(args, stream, format)
	case formatter.FormatGoTpl: // gotemplate
		fallthrough
	default:
		format.CMD.PrintErrln("Error: output format not supported")
		return
	}
}

// tableStreamEvents prints events in a table format
func tableStreamEvents(_ []string, stream pb.TraceeService_StreamEventsClient, tbl *formatter.Formatter) {
	// Init table header before streaming starts
	tbl.PrintSteamTableHeaders()
	// Receive and process streamed responses
	for {
		res, err := stream.Recv()
		if err != nil {
			// Handle the error that occurs when the server closes the stream
			if err.Error() == "EOF" {
				break
			}
			tbl.CMD.PrintErrln("Error receiving streamed event: ", err)
		}
		tbl.PrintStreamTableRow(res.Event)

	}
}

// jsonStreamEvents prints events in json format
func jsonStreamEvents(_ []string, stream pb.TraceeService_StreamEventsClient, tbl *formatter.Formatter) { // Receive and process streamed responses
	for {
		res, err := stream.Recv()
		if err != nil {
			// Handle the error that occurs when the server closes the stream
			if err.Error() == "EOF" {
				break
			}
			tbl.CMD.PrintErrln("Error receiving streamed event: ", err)
		}
		// Print each event as a row in json format
		tbl.PrintStreamJSON(res.Event)
	}
}

func ListEvents(format *formatter.Formatter, args []string, response *pb.GetEventDefinitionsResponse) {
	//this can add support for other output formats
	switch format.Format {
	case formatter.FormatJSON:
		jsonListEvent(format, args, response)
	case formatter.FormatTable:
		tableListEvent(format, args, response)
	case formatter.FormatGoTpl: // gotemplate
		fallthrough
	default:
		format.CMD.PrintErrln("Error: output format not supported")
		return
	}

}
func tableListEvent(format *formatter.Formatter, _ []string, response *pb.GetEventDefinitionsResponse) {
	tbl := format.PrintEventListTable(response)
	tbl.Render()
}
func jsonListEvent(format *formatter.Formatter, _ []string, response *pb.GetEventDefinitionsResponse) {
	format.PrintEventListJSON(response)
}
func DescribeEvent(format *formatter.Formatter, args []string, response *pb.GetEventDefinitionsResponse) {
	//this can add support for other output formats
	switch format.Format {
	case formatter.FormatJSON:
		jsonDescribeEvent(format, args, response)
	case formatter.FormatTable:
		tableDescribeEvent(format, args, response)
	case formatter.FormatGoTpl: // gotemplate
		fallthrough
	default:
		format.CMD.PrintErrln("Error: output format not supported")
		return
	}

}
func jsonDescribeEvent(format *formatter.Formatter, _ []string, response *pb.GetEventDefinitionsResponse) {
	format.PrintEventDescriptionJSON(response)
}
func tableDescribeEvent(format *formatter.Formatter, _ []string, response *pb.GetEventDefinitionsResponse) {
	tbl := format.PrintEventDescriptionTable(response)
	tbl.Render()
}
