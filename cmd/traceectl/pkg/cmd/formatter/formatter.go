package formatter

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	FormatJson  = "json"
	FormatTable = "table"
)

var SupportedFormats = []string{FormatJson, FormatTable}

type Formatter struct {
	format   string
	cmd      *cobra.Command
	paddings map[int][]int
}

func NewFormatter(format string, cmd *cobra.Command) (*Formatter, error) {
	switch format {
	case FormatJson:
		return &Formatter{
			format: format,
			cmd:    cmd,
		}, nil
	case FormatTable:
		// add padding for table
		return &Formatter{
			format: format,
			cmd:    cmd,
			paddings: map[int][]int{
				4: {20, 15, 15, 20},     // Padding for 4 columns
				5: {15, 10, 20, 15, 10}, // Padding for 5 columns
			},
		}, nil
	default:
		return nil, fmt.Errorf("format %s is not supported", format)
	}
}
func (f *Formatter) GetFormat() string {
	return f.format
}

// PrintTableHeaders prints table headers with padding based on their length.
func (f *Formatter) PrintTableHeaders(headers []string) {
	switch len(headers) {
	case 4:
		f.cmd.Printf("%-20s %-15s %-15s %-20s\n",
			headers[0],
			headers[1],
			headers[2],
			headers[3],
		)
	case 5:
		f.cmd.Printf("%-15s %-10s %-20s %-15s %-10s\n",
			headers[0],
			headers[1],
			headers[2],
			headers[3],
			headers[4],
		)
	default:
		f.cmd.Println("Error: Unsupported number of headers.")
	}
}

// PrintTableRow prints a single row with padding matching the header format.
func (f *Formatter) PrintTableRow(row []string) {
	switch len(row) {
	case 4:
		f.cmd.Printf("%-20s %-15s %-15s %-20s\n",
			row[0],
			row[1],
			row[2],
			row[3],
		)
	case 5:
		f.cmd.Printf("%-15s %-10s %-20s %-15s %-10s\n",
			row[0],
			row[1],
			row[2],
			row[3],
			row[4],
		)
	default:
		f.cmd.Println("Error: Unsupported number of columns in row.")
	}
}

func (f *Formatter) PrintJson(data interface{}) {
	f.cmd.Println(data)
}
