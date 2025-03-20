package printer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

const (
	TableFormat = "table"
	JsonFormat  = "json"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(metrics *pb.GetMetricsResponse)
	// Print prints a single event
	Print(event *pb.Event)
	// dispose of resources
	Close()
}

func New(cmd *cobra.Command, kind string) (EventPrinter, error) {
	var res EventPrinter
	switch kind {
	case TableFormat:
		res = &tableEventPrinter{
			cmd: cmd,
		}
	case JsonFormat:
		res = &jsonEventPrinter{
			cmd: cmd,
		}
	default:
		return res, fmt.Errorf("unsupported output type: %s", kind)
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

// table format
type tableEventPrinter struct {
	cmd *cobra.Command
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	p.cmd.Printf("%-15s %-25s %-20s %-15s %s\n",
		"TIME",
		"EVENT NAME",
		"POLICIES",
		"PID",
		"DATA",
	)
}

func (p tableEventPrinter) Epilogue(metrics *pb.GetMetricsResponse) {
	metricsJson, err := metrics.MarshalJSON()
	if err != nil {
		panic(err)
	}
	p.cmd.Printf("\n%s\n", metricsJson)
}

func (p tableEventPrinter) Print(event *pb.Event) {
	eventData, err := p.eventValuesToJSON(event.GetData())
	if err != nil {
		panic(1)
	}
	p.cmd.Printf("%-15s %-25s %-20s %-15s %s\n",
		event.Timestamp.AsTime().Format("15:04:05.00000"),
		event.Name,
		strings.Join(event.Policies.Matched, ","),
		strconv.Itoa(int(event.Context.Process.Pid.Value)),
		eventData,
	)
}

func (p tableEventPrinter) Close() {}

func (p tableEventPrinter) eventValuesToJSON(eventValues []*pb.EventValue) (string, error) {
	// Create a slice to hold the marshaled JSON objects
	jsonObjects := make([]json.RawMessage, len(eventValues))

	// Marshal each EventValue individually
	for i, ev := range eventValues {
		jsonObj, err := json.Marshal(ev)
		if err != nil {
			return "", fmt.Errorf("error marshaling EventValue: %w", err)
		}
		jsonObjects[i] = jsonObj
	}

	// Marshal the slice of JSON objects
	finalJSON, err := json.Marshal(jsonObjects)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON objects: %w", err)
	}

	return string(finalJSON), nil
}

// json format
type jsonEventPrinter struct {
	cmd *cobra.Command
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Epilogue(metrics *pb.GetMetricsResponse) {
	p.cmd.Printf("%s\n", metrics.String())
}

func (p jsonEventPrinter) Print(event *pb.Event) {
	eBytes, err := event.MarshalJSON()
	if err != nil {
		p.cmd.PrintErrf("error marshaling event to json: %s\n", err)
	}
	p.cmd.Printf("%s\n", string(eBytes))
}

func (p jsonEventPrinter) Close() {}
