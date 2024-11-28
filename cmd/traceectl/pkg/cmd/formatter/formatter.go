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
		//add padding for table
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
