package flags

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			testName:      "empty file for format",
			outputSlice:   []string{"json:"},
			expectedError: EmptyOutputFlagError("format"),
		},
		// formats
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: config.OutputConfig{
				DecodedData: true,
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
				DecodedData: true,
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
				DecodedData: true,
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
				DecodedData: true,
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
				DecodedData: true,
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
		{
			testName:    "sort-events",
			outputSlice: []string{"sort-events"},
			expectedOutput: config.OutputConfig{
				DecodedData:   true,
				EventsSorting: true,
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
			testName: "all valid output options",
			outputSlice: []string{
				"json",
				"sort-events",
			},
			expectedOutput: config.OutputConfig{
				EventsSorting: true,
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
				assert.Equal(t, testcase.expectedOutput.Environment, output.Environment)
				assert.Equal(t, testcase.expectedOutput.DecodedData, output.DecodedData)
				assert.Equal(t, testcase.expectedOutput.FdPaths, output.FdPaths)
				assert.Equal(t, testcase.expectedOutput.UserStack, output.UserStack)
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

func TestOutputConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   OutputConfig
		expected []string
	}{
		{
			name:     "empty config",
			config:   OutputConfig{},
			expected: []string{},
		},
		{
			name: "none option only",
			config: OutputConfig{
				None: true,
			},
			expected: []string{"none"},
		},
		{
			name: "sort-events option only",
			config: OutputConfig{
				SortEvents: true,
			},
			expected: []string{"sort-events"},
		},
		{
			name: "all options",
			config: OutputConfig{
				None:       true,
				SortEvents: true,
			},
			expected: []string{
				"none",
				"sort-events",
			},
		},
		{
			name: "single destination with format",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "d1",
						Format: "json",
					},
				},
			},
			expected: []string{"destinations.d1.format=json"},
		},
		{
			name: "single destination with type",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name: "d1",
						Type: "file",
					},
				},
			},
			expected: []string{"destinations.d1.type=file"},
		},
		{
			name: "single destination with path",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name: "d1",
						Path: "/tmp/output",
					},
				},
			},
			expected: []string{"destinations.d1.path=/tmp/output"},
		},
		{
			name: "single destination with url",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name: "d1",
						Url:  "http://localhost:8080",
					},
				},
			},
			expected: []string{"destinations.d1.url=http://localhost:8080"},
		},
		{
			name: "complete destination",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "d1",
						Type:   "webhook",
						Format: "json",
						Url:    "http://localhost:8080",
					},
				},
			},
			expected: []string{
				"destinations.d1.format=json",
				"destinations.d1.type=webhook",
				"destinations.d1.url=http://localhost:8080",
			},
		},
		{
			name: "multiple destinations",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "d1",
						Type:   "file",
						Format: "json",
						Path:   "/tmp/file1",
					},
					{
						Name:   "d2",
						Type:   "webhook",
						Format: "json",
						Url:    "http://localhost:8080",
					},
				},
			},
			expected: []string{
				"destinations.d1.format=json",
				"destinations.d1.type=file",
				"destinations.d1.path=/tmp/file1",
				"destinations.d2.format=json",
				"destinations.d2.type=webhook",
				"destinations.d2.url=http://localhost:8080",
			},
		},
		{
			name: "single stream with destinations",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name:         "s1",
						Destinations: []string{"d1", "d2"},
					},
				},
			},
			expected: []string{"streams.s1.destinations=d1,d2"},
		},
		{
			name: "single stream with filters events",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name: "s1",
						Filters: StreamFiltersConfig{
							Events: []string{"execve", "open"},
						},
					},
				},
			},
			expected: []string{"streams.s1.filters.events=execve,open"},
		},
		{
			name: "single stream with filters policies",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name: "s1",
						Filters: StreamFiltersConfig{
							Policies: []string{"policy1", "policy2"},
						},
					},
				},
			},
			expected: []string{"streams.s1.filters.policies=policy1,policy2"},
		},
		{
			name: "single stream with buffer mode",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name: "s1",
						Buffer: StreamBufferConfig{
							Mode: StreamBufferBlock,
						},
					},
				},
			},
			expected: []string{"streams.s1.buffer.mode=block"},
		},
		{
			name: "single stream with buffer size",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name: "s1",
						Buffer: StreamBufferConfig{
							Size: 1024,
						},
					},
				},
			},
			expected: []string{"streams.s1.buffer.size=1024"},
		},
		{
			name: "complete stream",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name:         "s1",
						Destinations: []string{"d1", "d2"},
						Filters: StreamFiltersConfig{
							Events:   []string{"execve", "open"},
							Policies: []string{"policy1"},
						},
						Buffer: StreamBufferConfig{
							Mode: StreamBufferDrop,
							Size: 2048,
						},
					},
				},
			},
			expected: []string{
				"streams.s1.destinations=d1,d2",
				"streams.s1.filters.events=execve,open",
				"streams.s1.filters.policies=policy1",
				"streams.s1.buffer.mode=drop",
				"streams.s1.buffer.size=2048",
			},
		},
		{
			name: "multiple streams",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name:         "s1",
						Destinations: []string{"d1"},
						Filters: StreamFiltersConfig{
							Events: []string{"execve"},
						},
					},
					{
						Name:         "s2",
						Destinations: []string{"d2"},
						Buffer: StreamBufferConfig{
							Mode: StreamBufferBlock,
							Size: 1024,
						},
					},
				},
			},
			expected: []string{
				"streams.s1.destinations=d1",
				"streams.s1.filters.events=execve",
				"streams.s2.destinations=d2",
				"streams.s2.buffer.mode=block",
				"streams.s2.buffer.size=1024",
			},
		},
		{
			name: "all components",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "d1",
						Type:   "file",
						Format: "json",
						Path:   "/tmp/output",
					},
				},
				Streams: []StreamConfig{
					{
						Name:         "s1",
						Destinations: []string{"d1"},
						Filters: StreamFiltersConfig{
							Events: []string{"execve"},
						},
						Buffer: StreamBufferConfig{
							Mode: StreamBufferBlock,
							Size: 1024,
						},
					},
				},
			},
			expected: []string{
				"destinations.d1.format=json",
				"destinations.d1.type=file",
				"destinations.d1.path=/tmp/output",
				"streams.s1.destinations=d1",
				"streams.s1.filters.events=execve",
				"streams.s1.buffer.mode=block",
				"streams.s1.buffer.size=1024",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}
