package printer_test

// import (
// 	"fmt"
// 	"os"
// 	"testing"

// 	"github.com/stretchr/testify/assert"

// 	"github.com/aquasecurity/tracee/pkg/cmd/flags"
// 	"github.com/aquasecurity/tracee/pkg/config"
// )

// func TestTraceeEbpfPrepareOutputPrinterConfig(t *testing.T) {
// 	t.Parallel()

// 	testCases := []struct {
// 		testName        string
// 		outputSlice     []string
// 		expectedPrinter config.PrinterConfig
// 		expectedError   error
// 	}{
// 		{
// 			testName:        "invalid format",
// 			outputSlice:     []string{"notaformat"},
// 			expectedPrinter: config.PrinterConfig{},
// 			expectedError:   fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', or 'gotemplate='. Use '--output help' for more info", "notaformat"),
// 		},
// 		{
// 			testName:        "invalid format with format prefix",
// 			outputSlice:     []string{"format:notaformat2"},
// 			expectedPrinter: config.PrinterConfig{},
// 			expectedError:   fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', or 'gotemplate='. Use '--output help' for more info", "notaformat2"),
// 		},
// 		{
// 			testName:    "default",
// 			outputSlice: []string{},
// 			expectedPrinter: config.PrinterConfig{
// 				Kind:    "table",
// 				OutFile: os.Stdout,
// 			},
// 			expectedError: nil,
// 		},
// 		{
// 			testName:    "format: json",
// 			outputSlice: []string{"format:json"},
// 			expectedPrinter: config.PrinterConfig{
// 				Kind:    "json",
// 				OutFile: os.Stdout,
// 			},
// 			expectedError: nil,
// 		},
// 	}
// 	for _, testcase := range testCases {
// 		testcase := testcase

// 		t.Run(testcase.testName, func(t *testing.T) {
// 			t.Parallel()

// 			outputConfig, err := flags.TraceeEbpfPrepareOutput(testcase.outputSlice, false)
// 			if err != nil {
// 				assert.ErrorContains(t, err, testcase.expectedError.Error())
// 			} else {
// 				assert.Equal(t, testcase.expectedPrinter, outputConfig.PrinterConfigs[0])
// 			}
// 		})
// 	}
// }
