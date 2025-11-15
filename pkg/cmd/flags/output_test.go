package flags

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/digest"
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
			expectedError: InvalidOutputFlagError("foo"),
		},
		{
			testName:      "empty option flag",
			outputSlice:   []string{"option"},
			expectedError: EmptyOutputFlagError("option"),
		},
		{
			testName:      "empty option flag 2",
			outputSlice:   []string{"option:"},
			expectedError: EmptyOutputFlagError("option"),
		},
		{
			testName:      "invalid option value",
			outputSlice:   []string{"option:foo"},
			expectedError: InvalidOutputOptionError("foo"),
		},
		{
			testName:      "empty file for format",
			outputSlice:   []string{"json:"},
			expectedError: EmptyOutputFlagError("format"),
		},
		// formats
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "/tmp/table"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
					{Type: "file", Format: "table", Path: "/tmp/table"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "json", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "json to /tmp/json, and json to /tmp/json2",
			outputSlice: []string{"json:/tmp/json", "json:/tmp/json2"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "json", Path: "/tmp/json"},
					{Type: "file", Format: "json", Path: "/tmp/json2"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "table-verbose to stdout",
			outputSlice: []string{"table-verbose"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table-verbose", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to stdout",
			outputSlice: []string{"gotemplate=template.tmpl"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "gotemplate=template.tmpl", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to multiple files",
			outputSlice: []string{"gotemplate=template.tmpl:/tmp/gotemplate1,/tmp/gotemplate2"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate1"},
					{Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate2"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
					{Type: "file", Format: "json", Path: "/tmp/json"},
					{Type: "file", Format: "json", Path: "/tmp/json2"},
					{Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate1"},
				},
				TraceeConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:      "two formats for stdout",
			outputSlice:   []string{"table", "json"},
			expectedError: DuplicateOutputPathError("stdout"),
		},
		{
			testName:      "format for the same file twice",
			outputSlice:   []string{"table:/tmp/test,/tmp/test"},
			expectedError: DuplicateOutputPathError("/tmp/test"),
		},
		{
			testName:      "two different formats for the same file",
			outputSlice:   []string{"table:/tmp/test", "json:/tmp/test"},
			expectedError: DuplicateOutputPathError("/tmp/test"),
		},
		{
			testName:    "none",
			outputSlice: []string{"none"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "ignore", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:      "invalid value for none format",
			outputSlice:   []string{"none:"},
			expectedError: NoneOutputPathError(),
		},
		{
			testName:      "invalid value for none format 2",
			outputSlice:   []string{"none:/tmp/test"},
			expectedError: NoneOutputPathError(),
		},
		// forward
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward"},
			expectedError: EmptyOutputFlagError("forward"),
		},
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward:"},
			expectedError: EmptyOutputFlagError("forward"),
		},
		{
			testName:      "invalid forward url",
			outputSlice:   []string{"forward:lalala"},
			expectedError: InvalidOutputURIError("forward", "lalala"),
		},
		{
			testName:    "forward",
			outputSlice: []string{"forward:tcp://localhost:1234"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "forward", Url: "tcp://localhost:1234"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		// webhook
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook"},
			expectedError: EmptyOutputFlagError("webhook"),
		},
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook:"},
			expectedError: EmptyOutputFlagError("webhook"),
		},
		{
			testName:      "invalid webhook url",
			outputSlice:   []string{"webhook:lalala"},
			expectedError: InvalidOutputURIError("webhook", "lalala"),
		},
		{
			testName:    "webhook",
			outputSlice: []string{"webhook:http://localhost:8080"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "webhook", Url: "http://localhost:8080", Format: "json"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		{
			testName:    "webhook with gotemplate",
			outputSlice: []string{"webhook:http://localhost:8080?gotemplate=/path/to/template"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "webhook", Url: "http://localhost:8080?gotemplate=/path/to/template", Format: "gotemplate=/path/to/template"},
				},
				TraceeConfig: &config.OutputConfig{},
			},
		},
		// options
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					CalcHashes:     digest.CalcHashesDevInode,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-hash=inode",
			outputSlice: []string{"option:exec-hash=inode"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					CalcHashes:     digest.CalcHashesInode,
					ParseArguments: true,
				},
			},
		},
		{
			testName:      "option exec-hash invalid",
			outputSlice:   []string{"option:exec-hash=notvalid"},
			expectedError: InvalidOutputOptionError("exec-hash=notvalid"),
		},
		{
			testName:      "option exec-hash invalid",
			outputSlice:   []string{"option:exec-hasha"},
			expectedError: InvalidOutputOptionError("exec-hasha"),
		},
		{
			testName:    "option parse-arguments",
			outputSlice: []string{"json", "option:parse-arguments"},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "json", Path: "stdout"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "json", Path: "stdout"},
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
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "table", Path: "stdout"},
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
				"option:exec-hash=dev-inode",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			expectedOutput: PrepareOutputResult{
				DestinationConfigs: []config.Destination{
					{Type: "file", Format: "json", Path: "stdout"},
				},
				TraceeConfig: &config.OutputConfig{
					StackAddresses:    true,
					ExecEnv:           true,
					CalcHashes:        digest.CalcHashesDevInode,
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
				for _, printer := range testcase.expectedOutput.DestinationConfigs {
					if strings.HasPrefix(printer.Path, "/tmp") {
						_ = os.Remove(printer.Path)
					}
				}
			}()

			output, err := PrepareOutput(testcase.outputSlice)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.TraceeConfig, output.TraceeConfig)

				assertPrinterConfigs(t, testcase.expectedOutput.DestinationConfigs, output.DestinationConfigs)
			}
		})
	}
}

func assertPrinterConfigs(t *testing.T, expected []config.Destination, actual []config.Destination) {
	// use a map to compare because the order of the printers is not guaranteed
	printersMap := make(map[string]config.Destination)

	for _, p := range expected {
		if p.Path != "" {
			printersMap[p.Path] = p
		} else {
			printersMap[p.Url] = p
		}
	}

	for _, p := range actual {
		var expectedPrinter config.Destination
		var ok bool
		if p.Path != "" {
			expectedPrinter, ok = printersMap[p.Path]
		} else {
			expectedPrinter, ok = printersMap[p.Url]
		}
		assert.True(t, ok)

		assert.Equal(t, expectedPrinter.Type, p.Type)
		assert.Equal(t, expectedPrinter.Path, p.Path)
		assert.Equal(t, expectedPrinter.Url, p.Url)
		assert.Equal(t, expectedPrinter.Format, p.Format)
		assert.Equal(t, expectedPrinter.ContainerMode, p.ContainerMode)
	}
}
