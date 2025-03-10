package flags

import (
	"fmt"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

const FormatFlag = "format"

func PrepareFormat(formatSlice string) (string, error) {
	switch formatSlice {
	case printer.TableFormat:
		return printer.TableFormat, nil
	case printer.JsonFormat:
		return printer.JsonFormat, nil
	default:
		return "", fmt.Errorf("unsupported format type: %s", formatSlice)
	}
}
