package flags

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/pkg/config"
)

func TestPrepareOutput(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput config.OutputConfig
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
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "table to stdout",
			outputSlice: []string{"table"},
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "table to /tmp/table",
			outputSlice: []string{"table:/tmp/table"},
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "/tmp/tabletable", Type: "file", Format: "table", Path: "/tmp/table"},
						},
					},
				},
			},
		},
		{
			testName:    "table to stdout, and to /tmp/table",
			outputSlice: []string{"table", "table:/tmp/table"},
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
							{Name: "/tmp/tabletable", Type: "file", Format: "table", Path: "/tmp/table"},
						},
					},
				},
			},
		},
		{
			testName:    "json to stdout",
			outputSlice: []string{"json"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdoutjson", Type: "file", Format: "json", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "json to /tmp/json, and json to /tmp/json2",
			outputSlice: []string{"json:/tmp/json", "json:/tmp/json2"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "/tmp/jsonjson", Type: "file", Format: "json", Path: "/tmp/json"},
							{Name: "/tmp/json2json", Type: "file", Format: "json", Path: "/tmp/json2"},
						},
					},
				},
			},
		},
		{
			testName:    "table-verbose to stdout",
			outputSlice: []string{"table-verbose"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable-verbose", Type: "file", Format: "table-verbose", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "gotemplate to stdout",
			outputSlice: []string{"gotemplate=template.tmpl"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdoutgotemplate=template.tmpl", Type: "file", Format: "gotemplate=template.tmpl", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "gotemplate to multiple files",
			outputSlice: []string{"gotemplate=template.tmpl:/tmp/gotemplate1,/tmp/gotemplate2"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "/tmp/gotemplate1gotemplate=template.tmpl", Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate1"},
							{Name: "/tmp/gotemplate2gotemplate=template.tmpl", Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate2"},
						},
					},
				},
			},
		},
		{
			testName: "multiple formats",
			outputSlice: []string{
				"table",
				"json:/tmp/json,/tmp/json2",
				"gotemplate=template.tmpl:/tmp/gotemplate1",
			},
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
							{Name: "/tmp/jsonjson", Type: "file", Format: "json", Path: "/tmp/json"},
							{Name: "/tmp/json2json", Type: "file", Format: "json", Path: "/tmp/json2"},
							{Name: "/tmp/gotemplate1gotemplate=template.tmpl", Type: "file", Format: "gotemplate=template.tmpl", Path: "/tmp/gotemplate1"},
						},
					},
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
			testName:       "none",
			outputSlice:    []string{"none"},
			expectedOutput: config.OutputConfig{},
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
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "tcp://localhost:1234forward", Type: "forward", Url: "tcp://localhost:1234"},
						},
					},
				},
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
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "http://localhost:8080webhook", Type: "webhook", Url: "http://localhost:8080", Format: "json"},
						},
					},
				},
			},
		},
		{
			testName:    "webhook with gotemplate",
			outputSlice: []string{"webhook:http://localhost:8080?gotemplate=/path/to/template"},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "http://localhost:8080?gotemplate=/path/to/templatewebhook", Type: "webhook",
								Url: "http://localhost:8080?gotemplate=/path/to/template", Format: "gotemplate=/path/to/template"},
						},
					},
				},
			},
		},
		// options
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: config.OutputConfig{
				StackAddresses: true,
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: config.OutputConfig{
				ExecEnv:        true,
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: config.OutputConfig{
				CalcHashes:     digest.CalcHashesDevInode,
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "option exec-hash=inode",
			outputSlice: []string{"option:exec-hash=inode"},
			expectedOutput: config.OutputConfig{
				CalcHashes:     digest.CalcHashesInode,
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
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
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdoutjson", Type: "file", Format: "json", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "option parse-arguments-fds",
			outputSlice: []string{"json", "option:parse-arguments-fds"},
			expectedOutput: config.OutputConfig{
				ParseArguments:    true,
				ParseArgumentsFDs: true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdoutjson", Type: "file", Format: "json", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: config.OutputConfig{
				ParseArguments: true,
				EventsSorting:  true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdouttable", Type: "file", Format: "table", Path: "stdout"},
						},
					},
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
			expectedOutput: config.OutputConfig{
				StackAddresses:    true,
				ExecEnv:           true,
				CalcHashes:        digest.CalcHashesDevInode,
				ParseArguments:    true,
				ParseArgumentsFDs: true,
				EventsSorting:     true,
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "stdoutjson", Type: "file", Format: "json", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName: "define a json file destination",
			outputSlice: []string{
				"destinations.d1.format=json",
				"destinations.d1.type=file",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d1", Type: "file", Format: "json", Path: "stdout"},
						},
					},
				},
			},
		},
		{
			testName: "define a table file destination",
			outputSlice: []string{
				"destinations.d2.format=table",
				"destinations.d2.type=file",
				"destinations.d2.path=" + path.Join(tempDir, "tablefile"),
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "file", Format: "table", Path: path.Join(tempDir, "tablefile")},
						},
					},
				},
			},
		},
		{
			testName: "define a table file destination",
			outputSlice: []string{
				"destinations.d2.format=table",
				"destinations.d2.type=file",
				"destinations.d2.path=" + path.Join(tempDir, "tablefile"),
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "file", Format: "table", Path: path.Join(tempDir, "tablefile")},
						},
					},
				},
			},
		},
		{
			testName: "define a webhook destination",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=webhook",
				"destinations.d2.url=http://localhost:8080",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "webhook", Format: "json", Url: "http://localhost:8080"},
						},
					},
				},
			},
		},
		{
			testName: "define a forward destination",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
				"destinations.d2.url=tcp://localhost:8080",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "forward", Format: "json", Url: "tcp://localhost:8080"},
						},
					},
				},
			},
		},
		{
			testName: "define multiple destinations without streams",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
				"destinations.d2.url=tcp://localhost:8080",
				"destinations.d3.format=json",
				"destinations.d3.path=" + path.Join(tempDir, "jsonfilemultdest"),
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "forward", Format: "json", Url: "tcp://localhost:8080"},
							{Name: "d3", Type: "file", Format: "json", Path: path.Join(tempDir, "jsonfilemultdest")},
						},
					},
				},
			},
		},
		{
			testName: "define multiple destinations with different streams",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
				"destinations.d2.url=tcp://localhost:8080",
				"destinations.d3.format=json",
				"destinations.d3.path=" + path.Join(tempDir, "jsonfilemultdest"),
				"streams.s2.destinations=d2",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "s2",
						Destinations: []config.Destination{
							{Name: "d2", Type: "forward", Format: "json", Url: "tcp://localhost:8080"},
						},
					},
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d3", Type: "file", Format: "json", Path: path.Join(tempDir, "jsonfilemultdest")},
						},
					},
				},
			},
		},
		{
			testName: "no default-stream",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
				"destinations.d2.url=tcp://localhost:8080",
				"destinations.d3.format=json",
				"destinations.d3.path=" + path.Join(tempDir, "jsonfilemultdest"),
				"streams.s2.destinations=d2",
				"streams.s3.destinations=d3",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "s2",
						Destinations: []config.Destination{
							{Name: "d2", Type: "forward", Format: "json", Url: "tcp://localhost:8080"},
						},
					},
					{
						Name: "s3",
						Destinations: []config.Destination{
							{Name: "d3", Type: "file", Format: "json", Path: path.Join(tempDir, "jsonfilemultdest")},
						},
					},
				},
			},
		},
		{
			testName: "single stream with multiple destinations",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
				"destinations.d2.url=tcp://localhost:8080",
				"destinations.d3.format=json",
				"destinations.d3.path=" + path.Join(tempDir, "jsonfilemultdest"),
				"streams.stream.destinations=d2,d3",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "stream",
						Destinations: []config.Destination{
							{Name: "d2", Type: "forward", Format: "json", Url: "tcp://localhost:8080"},
							{Name: "d3", Type: "file", Format: "json", Path: path.Join(tempDir, "jsonfilemultdest")},
						},
					},
				},
			},
		},
		{
			testName: "webhook without url",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=webhook",
			},
			expectedError: MandatoryDestinationFieldError("webhook", "d2"),
		},
		{
			testName: "forward without url",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
			},
			expectedError: MandatoryDestinationFieldError("forward", "d2"),
		},
		{
			testName: "forward without url",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=forward",
			},
			expectedError: MandatoryDestinationFieldError("forward", "d2"),
		},
		{
			testName: "webhook without url",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=webhook",
			},
			expectedError: MandatoryDestinationFieldError("webhook", "d2"),
		},
		{
			testName: "invalid destination format field",
			outputSlice: []string{
				"destinations.d2.format=invalid",
				"destinations.d2.type=file",
			},
			expectedError: InvalidDestinationFieldError("format", "invalid", "d2"),
		},
		{
			testName: "invalid destination type field",
			outputSlice: []string{
				"destinations.d2.format=json",
				"destinations.d2.type=invalid",
			},
			expectedError: InvalidDestinationFieldError("type", "invalid", "d2"),
		},
		{
			testName: "all valid types",
			outputSlice: []string{
				"destinations.d1.format=json",
				"destinations.d2.type=webhook",
				"destinations.d2.url=http://localhost:8080",
				"destinations.d3.type=forward",
				"destinations.d3.url=tcp://localhost:8080",
				"destinations.d4.format=table",
				"destinations.d5.format=table-verbose",
			},
			expectedOutput: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{Name: "d1", Format: "json", Path: "stdout", Type: "file"},
							{Name: "d2", Format: "json", Url: "http://localhost:8080", Type: "webhook"},
							{Name: "d3", Format: "json", Url: "tcp://localhost:8080", Type: "forward"},
							{Name: "d4", Format: "table", Path: "stdout", Type: "file"},
							{Name: "d5", Format: "table-verbose", Path: "stdout", Type: "file"},
						},
					},
				},
			},
		},
		{
			testName: "wrong destination flag format",
			outputSlice: []string{
				"destinations.d1.type",
			},
			expectedError: DestinationFlagIncorrectError("destinations.d1.type"),
		},
		{
			testName: "wrong destination flag format",
			outputSlice: []string{
				"destinations.d1.type.wrong=invalid",
			},
			expectedError: DestinationFlagIncorrectError("destinations.d1.type.wrong=invalid"),
		},
		{
			testName: "wrong destination field",
			outputSlice: []string{
				"destinations.d1.invalid",
			},
			expectedError: DestinationFlagIncorrectError("destinations.d1.invalid"),
		},
		{
			testName: "wrong stream field",
			outputSlice: []string{
				"destinations.d1.type=file",
				"streams.s1.invalid=123",
			},
			expectedError: StreamFlagIncorrect("streams.s1.invalid=123"),
		},
	}

	for _, testcase := range testCases {
		// testcase := testcase

		t.Run(testcase.testName, func(t *testing.T) {
			t.Parallel()

			defer func() {
				for _, stream := range testcase.expectedOutput.Streams {
					for _, destination := range stream.Destinations {
						if strings.HasPrefix(destination.Path, "/tmp") {
							_ = os.Remove(destination.Path)
						}
					}
				}
			}()

			output, err := PrepareOutput(testcase.outputSlice, config.ContainerModeDisabled)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.CalcHashes, output.CalcHashes)
				assert.Equal(t, testcase.expectedOutput.EventsSorting, output.EventsSorting)
				assert.Equal(t, testcase.expectedOutput.ExecEnv, output.ExecEnv)
				assert.Equal(t, testcase.expectedOutput.ParseArguments, output.ParseArguments)
				assert.Equal(t, testcase.expectedOutput.ParseArgumentsFDs, output.ParseArgumentsFDs)
				assert.Equal(t, testcase.expectedOutput.StackAddresses, output.StackAddresses)
				assert.Equal(t, len(testcase.expectedOutput.Streams), len(output.Streams))

				assertPrinterConfigs(t, testcase.expectedOutput.Streams, output.Streams)
			}
		})
	}
}

func assertPrinterConfigs(t *testing.T, expected []config.Stream, actual []config.Stream) {
	// use a map to compare because the order of the printers is not guaranteed
	expectedStreamsMap := make(map[string]config.Stream)

	for _, stream := range expected {
		expectedStreamsMap[stream.Name] = stream
	}

	for _, actualStream := range actual {
		expectedDestsMap := map[string]config.Destination{}
		var expectedDest config.Destination
		var ok bool

		expectedStream, ok := expectedStreamsMap[actualStream.Name]
		assert.True(t, ok)
		for _, expectedDest := range expectedStream.Destinations {
			expectedDestsMap[expectedDest.Name] = expectedDest
		}

		for _, actualDest := range actualStream.Destinations {
			expectedDest, ok = expectedDestsMap[actualDest.Name]
			assert.True(t, ok)

			assert.Equal(t, expectedDest.Type, actualDest.Type)
			assert.Equal(t, expectedDest.Path, actualDest.Path)
			assert.Equal(t, expectedDest.Url, actualDest.Url)
			if expectedDest.Format != actualDest.Format {
				t.Errorf("%+v", actual)
			}
			assert.Equal(t, expectedDest.Format, actualDest.Format)
			assert.Equal(t, expectedDest.ContainerMode, actualDest.ContainerMode)
		}
	}
}
