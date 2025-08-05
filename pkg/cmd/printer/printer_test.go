package printer_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestTraceeEbpfPrepareOutputPrinterConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName        string
		outputSlice     []string
		expectedPrinter config.PrinterConfig
		expectedError   error
	}{
		{
			testName:        "invalid format",
			outputSlice:     []string{"notaformat"},
			expectedPrinter: config.PrinterConfig{},
			expectedError:   flags.UnrecognizedOutputFormatError("notaformat"),
		},
		{
			testName:        "invalid format with format prefix",
			outputSlice:     []string{"format:notaformat2"},
			expectedPrinter: config.PrinterConfig{},
			expectedError:   flags.UnrecognizedOutputFormatError("notaformat2"),
		},
		{
			testName:    "default",
			outputSlice: []string{},
			expectedPrinter: config.PrinterConfig{
				Kind:    "table",
				OutFile: os.Stdout,
			},
			expectedError: nil,
		},
		{
			testName:    "format: json",
			outputSlice: []string{"format:json"},
			expectedPrinter: config.PrinterConfig{
				Kind:    "json",
				OutFile: os.Stdout,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		testcase := testcase

		t.Run(testcase.testName, func(t *testing.T) {
			t.Parallel()

			outputConfig, err := flags.TraceeEbpfPrepareOutput(testcase.outputSlice, false)
			if err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedPrinter, outputConfig.PrinterConfigs[0])
			}
		})
	}
}

// bufferWriteCloser wraps bytes.Buffer to implement io.WriteCloser
type bufferWriteCloser struct {
	*bytes.Buffer
}

func (b *bufferWriteCloser) Close() error { return nil }

func TestTemplateEventPrinterSprigFunctions(t *testing.T) {
	t.Parallel()

	// Create a temporary template file that uses Sprig functions
	templateContent := `{"event_data": {{ toJson .Args }}, "process": "{{ .ProcessName | upper }}", "timestamp": {{ .Timestamp }}}`

	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "sprig_test.tmpl")

	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	// Create a buffer that implements WriteCloser
	buf := &bufferWriteCloser{Buffer: &bytes.Buffer{}}

	// Create printer config
	cfg := config.PrinterConfig{
		Kind:    "gotemplate=" + templatePath,
		OutFile: buf,
	}

	// Create and initialize the printer
	p, err := printer.New(cfg)
	require.NoError(t, err)

	err = p.Init()
	require.NoError(t, err, "Failed to initialize printer with Sprig functions - this indicates the fix didn't work")

	// Create a sample event
	sampleEvent := trace.Event{
		ProcessName: "test_process",
		Timestamp:   1234567890,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "arg1", Type: "string"}, Value: "value1"},
			{ArgMeta: trace.ArgMeta{Name: "arg2", Type: "int"}, Value: 42},
		},
	}

	// Test printing the event
	p.Preamble()
	p.Print(sampleEvent)
	p.Close()

	// Verify the output contains properly formatted JSON and uppercase process name
	output := buf.String()

	// Should contain JSON-formatted args (toJson function working)
	assert.Contains(t, output, `"arg1"`, "toJson function should format Args as JSON")
	assert.Contains(t, output, `"value1"`, "toJson should include argument values")
	assert.Contains(t, output, `42`, "toJson should include numeric values")

	// Should contain uppercase process name (upper function working)
	assert.Contains(t, output, `"TEST_PROCESS"`, "upper function should convert process name to uppercase")

	// Should contain timestamp
	assert.Contains(t, output, `1234567890`, "timestamp should be included")
}
