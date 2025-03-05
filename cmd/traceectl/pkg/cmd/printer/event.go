package printer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/table"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

const (
	EventList       = "list"
	EventDefinition = "definition"
)

type DescribeEventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue()
	// Print prints a single event
	Print(definition *pb.EventDefinition)
	// dispose of resources
	Close()
}

func NewDescribeEventPrinter(cmd *cobra.Command, format string) (DescribeEventPrinter, error) {
	var res DescribeEventPrinter
	switch format {
	case TableFormat:
		res = &tableDescribeEventsPrinter{
			cmd: cmd,
		}
	case JsonFormat:
		res = &jsonDescribeEventsPrinter{
			cmd: cmd,
		}
	default:
		return nil, fmt.Errorf("unsupported output type: %s", format)
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

// table format
type tableDescribeEventsPrinter struct {
	tbl *table.Table
	cmd *cobra.Command
}

func (p *tableDescribeEventsPrinter) Preamble() {
	p.tbl.SetHeaders(
		"ID",
		"NAME",
		"Version",
		"Tags",
		"Description",
	)
}

func (p *tableDescribeEventsPrinter) Print(definition *pb.EventDefinition) {
	p.tbl.AddRow(
		strconv.Itoa(int(definition.Id)),
		definition.Name,
		fmt.Sprintf("%d.%d.%d", definition.Version.Major, definition.Version.Minor, definition.Version.Patch),
		strings.Join(definition.Tags, ", "),
		definition.Description,
	)
}

func (p *tableDescribeEventsPrinter) Init() error {
	p.tbl = table.New(p.cmd.OutOrStdout())
	return nil
}

func (p *tableDescribeEventsPrinter) Epilogue() {
	p.tbl.Render()
}

func (p *tableDescribeEventsPrinter) Close() {}

// json format
type jsonDescribeEventsPrinter struct {
	cmd *cobra.Command
}

func (p *jsonDescribeEventsPrinter) Print(definition *pb.EventDefinition) {
	eBytes, err := definition.MarshalJSON()
	if err != nil {
		p.cmd.PrintErrf("error marshaling definition to json: %s\n", err)
	}
	p.cmd.Printf("%s\n", string(eBytes))
}

func (p *jsonDescribeEventsPrinter) Init() error { return nil }

func (p *jsonDescribeEventsPrinter) Preamble() {}

func (p *jsonDescribeEventsPrinter) Epilogue() {}

func (p *jsonDescribeEventsPrinter) Close() {}
