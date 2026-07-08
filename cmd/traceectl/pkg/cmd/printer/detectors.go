package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/table"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

type ListDetectorsPrinter interface {
	Init() error
	Preamble()
	Epilogue()
	Print(entry *pb.DetectorCatalogEntry)
	Close()
}

func NewListDetectorsPrinter(cmd *cobra.Command, format string) (ListDetectorsPrinter, error) {
	var res ListDetectorsPrinter
	switch format {
	case TableFormat:
		res = &tableListDetectorsPrinter{cmd: cmd}
	case JsonFormat:
		res = &jsonListDetectorsPrinter{cmd: cmd}
	default:
		return nil, fmt.Errorf("unsupported output type: %s", format)
	}
	if err := res.Init(); err != nil {
		return nil, err
	}
	return res, nil
}

type tableListDetectorsPrinter struct {
	tbl *table.Table
	cmd *cobra.Command
}

func (p *tableListDetectorsPrinter) Init() error {
	p.tbl = table.New(p.cmd.OutOrStdout())
	return nil
}

func (p *tableListDetectorsPrinter) Preamble() {
	p.tbl.SetHeaders(
		"DETECTOR_ID",
		"DETECTOR_NAME",
		"EVENT_NAME",
		"VERSION",
		"TAGS",
	)
}

func (p *tableListDetectorsPrinter) Print(entry *pb.DetectorCatalogEntry) {
	version := ""
	if v := entry.GetVersion(); v != nil {
		version = fmt.Sprintf("%d.%d.%d", v.GetMajor(), v.GetMinor(), v.GetPatch())
	}

	p.tbl.AddRow(
		entry.GetDetectorId(),
		entry.GetDetectorName(),
		entry.GetEventName(),
		version,
		strings.Join(entry.GetTags(), ", "),
	)
}

func (p *tableListDetectorsPrinter) Epilogue() {
	p.tbl.Render()
}

func (p *tableListDetectorsPrinter) Close() {}

type jsonListDetectorsPrinter struct {
	cmd     *cobra.Command
	entries []*pb.DetectorCatalogEntry
}

func (p *jsonListDetectorsPrinter) Init() error {
	p.entries = make([]*pb.DetectorCatalogEntry, 0)
	return nil
}

func (p *jsonListDetectorsPrinter) Preamble() {}

func (p *jsonListDetectorsPrinter) Print(entry *pb.DetectorCatalogEntry) {
	p.entries = append(p.entries, entry)
}

func (p *jsonListDetectorsPrinter) Epilogue() {
	out, err := json.MarshalIndent(p.entries, "", "  ")
	if err != nil {
		p.cmd.PrintErrf("error marshaling detectors to json: %s\n", err)
		return
	}
	p.cmd.Printf("%s\n", string(out))
}

func (p *jsonListDetectorsPrinter) Close() {}

type DescribeDetectorPrinter interface {
	Init() error
	Preamble()
	Epilogue()
	Print(entry *pb.DetectorCatalogEntry)
	Close()
}

func NewDescribeDetectorPrinter(cmd *cobra.Command, format string) (DescribeDetectorPrinter, error) {
	var res DescribeDetectorPrinter
	switch format {
	case TableFormat:
		res = &tableDescribeDetectorPrinter{cmd: cmd}
	case JsonFormat:
		res = &jsonDescribeDetectorPrinter{cmd: cmd}
	default:
		return nil, fmt.Errorf("unsupported output type: %s", format)
	}
	if err := res.Init(); err != nil {
		return nil, err
	}
	return res, nil
}

type tableDescribeDetectorPrinter struct {
	tbl *table.Table
	cmd *cobra.Command
}

func (p *tableDescribeDetectorPrinter) Init() error {
	p.tbl = table.New(p.cmd.OutOrStdout())
	return nil
}

func (p *tableDescribeDetectorPrinter) Preamble() {
	p.tbl.SetHeaders("FIELD", "VALUE")
}

func (p *tableDescribeDetectorPrinter) Print(entry *pb.DetectorCatalogEntry) {
	version := ""
	if v := entry.GetVersion(); v != nil {
		version = fmt.Sprintf("%d.%d.%d", v.GetMajor(), v.GetMinor(), v.GetPatch())
	}

	p.tbl.AddRow("DETECTOR_ID", entry.GetDetectorId())
	p.tbl.AddRow("DETECTOR_NAME", entry.GetDetectorName())
	p.tbl.AddRow("EVENT_NAME", entry.GetEventName())
	p.tbl.AddRow("VERSION", version)
	p.tbl.AddRow("DESCRIPTION", entry.GetDescription())
	p.tbl.AddRow("TAGS", strings.Join(entry.GetTags(), ", "))

	keys := make([]string, 0, len(entry.GetProperties()))
	for key := range entry.GetProperties() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p.tbl.AddRow("PROPERTY:"+key, entry.GetProperties()[key])
	}
}

func (p *tableDescribeDetectorPrinter) Epilogue() {
	p.tbl.Render()
}

func (p *tableDescribeDetectorPrinter) Close() {}

type jsonDescribeDetectorPrinter struct {
	cmd     *cobra.Command
	entries []*pb.DetectorCatalogEntry
}

func (p *jsonDescribeDetectorPrinter) Init() error {
	p.entries = make([]*pb.DetectorCatalogEntry, 0)
	return nil
}

func (p *jsonDescribeDetectorPrinter) Preamble() {}

func (p *jsonDescribeDetectorPrinter) Print(entry *pb.DetectorCatalogEntry) {
	p.entries = append(p.entries, entry)
}

func (p *jsonDescribeDetectorPrinter) Epilogue() {
	out, err := json.MarshalIndent(p.entries, "", "  ")
	if err != nil {
		p.cmd.PrintErrf("error marshaling detector to json: %s\n", err)
		return
	}
	p.cmd.Printf("%s\n", string(out))
}

func (p *jsonDescribeDetectorPrinter) Close() {}
