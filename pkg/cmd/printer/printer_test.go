package printer_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
)

func TestTraceeEbpfPrepareOutputPrinterConfig(t *testing.T) {

	testCases := []struct {
		testName        string
		outputSlice     []string
		expectedPrinter printer.Config
		expectedError   error
	}{
		{
			testName:        "invalid format",
			outputSlice:     []string{"notaformat"},
			expectedPrinter: printer.Config{},
			expectedError:   fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info", "notaformat"),
		},
		{
			testName:        "invalid format with format prefix",
			outputSlice:     []string{"format:notaformat2"},
			expectedPrinter: printer.Config{},
			expectedError:   fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info", "notaformat2"),
		},
		{
			testName:    "default",
			outputSlice: []string{},
			expectedPrinter: printer.Config{
				Kind:    "table",
				OutFile: os.Stdout,
			},
			expectedError: nil,
		},
		{
			testName:    "format: json",
			outputSlice: []string{"format:json"},
			expectedPrinter: printer.Config{
				Kind:    "json",
				OutFile: os.Stdout,
			},
			expectedError: nil,
		},
		{
			testName:    "option relative timestamp",
			outputSlice: []string{"option:relative-time"},
			expectedPrinter: printer.Config{
				Kind:       "table",
				OutFile:    os.Stdout,
				RelativeTS: true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			outputConfig, err := flags.TraceeEbpfPrepareOutput(testcase.outputSlice)
			if err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedPrinter, outputConfig.PrinterConfigs[0])
			}
		})
	}
}
