package flags

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/config"
)

func TestPrepareOutput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput PrepareOutputResult
		expectedError  error
	}{
		// validations
		{
			testName:      "invalid output flag",
			outputSlice:   []string{"foo"},
			expectedError: errors.New("invalid output flag: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty option flag",
			outputSlice:   []string{"option"},
			expectedError: errors.New("parseOption: option flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty option flag 2",
			outputSlice:   []string{"option:"},
			expectedError: errors.New("parseOption: option flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid option value",
			outputSlice:   []string{"option:foo"},
			expectedError: errors.New("setOption: invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty file for format",
			outputSlice:   []string{"json:"},
			expectedError: errors.New("parseFormat: format flag can't be empty, use '--output help' for more info"),
		},
		// formats
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to stdout",
			outputSlice: []string{"table"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to /tmp/table",
			outputSlice: []string{"table:/tmp/table"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "/tmp/table"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to stdout, and to /tmp/table",
			outputSlice: []string{"table", "table:/tmp/table"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
					{Kind: "table", OutPath: "/tmp/table"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "json to stdout",
			outputSlice: []string{"json"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "json to /tmp/json, and json to /tmp/json2",
			outputSlice: []string{"json:/tmp/json", "json:/tmp/json2"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "/tmp/json"},
					{Kind: "json", OutPath: "/tmp/json2"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "table-verbose to stdout",
			outputSlice: []string{"table-verbose"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table-verbose", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to stdout",
			outputSlice: []string{"gotemplate=template.tmpl"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "gotemplate=template.tmpl", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to multiple files",
			outputSlice: []string{"gotemplate=template.tmpl:/tmp/gotemplate1,/tmp/gotemplate2"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate1"},
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate2"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName: "multiple formats",
			outputSlice: []string{
				"table",
				"json:/tmp/json,/tmp/json2",
				"gotemplate=template.tmpl:/tmp/gotemplate1",
			},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
					{Kind: "json", OutPath: "/tmp/json"},
					{Kind: "json", OutPath: "/tmp/json2"},
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate1"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:      "two formats for stdout",
			outputSlice:   []string{"table", "json"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: stdout, use '--output help' for more info"),
		},
		{
			testName:      "format for the same file twice",
			outputSlice:   []string{"table:/tmp/test,/tmp/test"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: /tmp/test, use '--output help' for more info"),
		},
		{
			testName:      "two different formats for the same file",
			outputSlice:   []string{"table:/tmp/test", "json:/tmp/test"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: /tmp/test, use '--output help' for more info"),
		},
		{
			testName:    "none",
			outputSlice: []string{"none"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "ignore", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:      "invalid value for none format",
			outputSlice:   []string{"none:"},
			expectedError: errors.New("none output does not support path. Use '--output help' for more info"),
		},
		{
			testName:      "invalid value for none format 2",
			outputSlice:   []string{"none:/tmp/test"},
			expectedError: errors.New("none output does not support path. Use '--output help' for more info"),
		},
		// forward
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward"},
			expectedError: errors.New("validateURL: forward flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward:"},
			expectedError: errors.New("validateURL: forward flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid forward url",
			outputSlice:   []string{"forward:lalala"},
			expectedError: errors.New("validateURL: invalid uri for forward output \"lalala\". Use '--output help' for more info"),
		},
		{
			testName:    "forward",
			outputSlice: []string{"forward:tcp://localhost:1234"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "forward", OutPath: "tcp://localhost:1234"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		// webhook
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook"},
			expectedError: errors.New("validateURL: webhook flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook:"},
			expectedError: errors.New("validateURL: webhook flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid webhook url",
			outputSlice:   []string{"webhook:lalala"},
			expectedError: errors.New("validateURL: invalid uri for webhook output \"lalala\". Use '--output help' for more info"),
		},
		{
			testName:    "webhook",
			outputSlice: []string{"webhook:http://localhost:8080"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "webhook", OutPath: "http://localhost:8080"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		// options
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					StackAddresses: true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option relative-time",
			outputSlice: []string{"json", "option:relative-time"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "stdout", RelativeTS: true},
				},
				TraceeConfig: &config.OutputConfig{
					RelativeTime: true,
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					CalcHashes:     config.CalcHashesDevInode,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-hash=inode",
			outputSlice: []string{"option:exec-hash=inode"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					CalcHashes:     config.CalcHashesInode,
					ParseArguments: true,
				},
			},
		},
		{
			testName:      "option exec-hash invalid",
			outputSlice:   []string{"option:exec-hash=notvalid"},
			expectedError: errors.New("invalid output option: exec-hash=notvalid, use '--output help' for more info"),
		},
		{
			testName:      "option exec-hash invalid",
			outputSlice:   []string{"option:exec-hasha"},
			expectedError: errors.New("invalid output option: exec-hasha, use '--output help' for more info"),
		},
		{
			testName:    "option parse-arguments",
			outputSlice: []string{"json", "option:parse-arguments"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments-fds",
			outputSlice: []string{"json", "option:parse-arguments-fds"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments:    true,
					ParseArgumentsFDs: true,
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
		},
		{
			testName: "all options",
			outputSlice: []string{
				"json",
				"option:stack-addresses",
				"option:exec-env",
				"option:relative-time",
				"option:exec-hash=dev-inode",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			expectedOutput: PrepareOutputResult{
				PrinterConfigs: []config.PrinterConfig{
					{Kind: "json", OutPath: "stdout", RelativeTS: true},
				},
				TraceeConfig: &config.OutputConfig{
					StackAddresses:    true,
					ExecEnv:           true,
					RelativeTime:      true,
					CalcHashes:        config.CalcHashesDevInode,
					ParseArguments:    true,
					ParseArgumentsFDs: true,
					EventsSorting:     true,
				},
			},
		},
	}
	for _, testcase := range testCases {
		// testcase := testcase

		t.Run(testcase.testName, func(t *testing.T) {
			// t.Parallel()

			defer func() {
				for _, printer := range testcase.expectedOutput.PrinterConfigs {
					if strings.HasPrefix(printer.OutPath, "/tmp") {
						_ = os.Remove(printer.OutPath)
					}
				}
			}()

			output, err := PrepareOutput(testcase.outputSlice, false)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.TraceeConfig, output.TraceeConfig)

				assertPrinterConfigs(t, testcase.expectedOutput.PrinterConfigs, output.PrinterConfigs)
			}
		})
	}
}

func assertPrinterConfigs(t *testing.T, expected []config.PrinterConfig, actual []config.PrinterConfig) {
	// use a map to compare because the order of the printers is not guaranteed
	printersMap := make(map[string]config.PrinterConfig)

	for _, p := range expected {
		printersMap[p.OutPath] = p
	}

	for _, p := range actual {
		expectedPrinter, ok := printersMap[p.OutPath]
		assert.True(t, ok)

		assert.Equal(t, expectedPrinter.Kind, p.Kind)
		assert.Equal(t, expectedPrinter.OutPath, p.OutPath)
		assert.Equal(t, expectedPrinter.RelativeTS, p.RelativeTS)
		assert.Equal(t, expectedPrinter.ContainerMode, p.ContainerMode)
	}
}
