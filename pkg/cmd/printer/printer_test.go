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
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// bufferWriteCloser wraps bytes.Buffer to implement io.WriteCloser
type bufferWriteCloser struct {
	*bytes.Buffer
}

func (b *bufferWriteCloser) Close() error { return nil }

func TestTemplateEventPrinterSprigFunctions(t *testing.T) {
	t.Parallel()

	// Create a temporary template file that uses Sprig functions
	// Note: pb.Event uses .Name instead of .EventName, .Data instead of .Args,
	// .Workload.Process.Thread.Name instead of .ProcessName
	templateContent := `{"event_data": {{ toJson .Data }}, "process": "{{ if .Workload }}{{ if .Workload.Process }}{{ if .Workload.Process.Thread }}{{ .Workload.Process.Thread.Name | upper }}{{ end }}{{ end }}{{ end }}", "timestamp": {{ if .Timestamp }}{{ .Timestamp.Seconds }}{{ else }}0{{ end }}}`

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
		Timestamp:   1234567890000000000, // nanoseconds - will be converted to seconds in pb.Timestamp
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "arg1", Type: "string"}, Value: "value1"},
			{ArgMeta: trace.ArgMeta{Name: "arg2", Type: "int"}, Value: 42},
		},
	}

	// Convert to pb.Event
	pbEvent, err := events.ConvertTraceeEventToProto(sampleEvent)
	require.NoError(t, err)

	// Test printing the event
	p.Preamble()
	p.Print(pbEvent)
	p.Close()

	// Verify the output contains properly formatted JSON and uppercase process name
	output := buf.String()

	// Should contain JSON-formatted data (toJson function working)
	// pb.Event uses .Data instead of .Args, and each data item has .Name and .Value
	assert.Contains(t, output, `"name"`, "toJson function should format Data as JSON")
	assert.Contains(t, output, `"arg1"`, "toJson should include argument names")

	// Should contain uppercase process name (upper function working)
	assert.Contains(t, output, `"TEST_PROCESS"`, "upper function should convert process name to uppercase")

	// Should contain timestamp (as seconds)
	assert.Contains(t, output, `1234567890`, "timestamp should be included")
}

// TestPrinterCloseFlushesData tests that Close() calls Sync() to flush buffered data to disk
func TestPrinterCloseFlushesData(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		printerKind string
	}{
		{
			name:        "json printer",
			printerKind: "json",
		},
		{
			name:        "table printer",
			printerKind: "table",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a temporary file
			tempDir := t.TempDir()
			outputPath := filepath.Join(tempDir, "test_output.txt")

			// Create the output file
			file, err := flags.CreateOutputFile(outputPath)
			require.NoError(t, err)
			defer file.Close() // We close it since we created it

			// Create printer config
			cfg := config.PrinterConfig{
				Kind:    tc.printerKind,
				OutFile: file,
			}

			// Create and initialize the printer
			p, err := printer.New(cfg)
			require.NoError(t, err)

			// Create a sample event
			sampleEvent := trace.Event{
				ProcessName: "test_process",
				EventID:     1,
				EventName:   "test_event",
				Timestamp:   1234567890,
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "arg1", Type: "string"}, Value: "value1"},
				},
			}

			// Convert to pb.Event
			pbEvent, err := events.ConvertTraceeEventToProto(sampleEvent)
			require.NoError(t, err)

			// Print an event
			p.Preamble()
			p.Print(pbEvent)
			p.Close() // This should flush the buffer via Sync()

			// Read the file content (file is still open, but Sync() should have flushed data to disk)
			content, err := os.ReadFile(outputPath)
			require.NoError(t, err, "Should be able to read flushed data while file is still open")

			// Verify data was written and flushed
			assert.NotEmpty(t, content, "File should contain data after Sync()")
			assert.Contains(t, string(content), "test_process", "File should contain event data")
		})
	}
}

// TestTemplateEventPrinterCloseFlushesData tests that template printer Close() calls Sync() to flush data
func TestTemplateEventPrinterCloseFlushesData(t *testing.T) {
	t.Parallel()

	// Create a temporary template file
	// Note: pb.Event uses .Name instead of .EventName, .Workload.Process.Thread.Name instead of .ProcessName
	templateContent := `{"event": "{{ .Name }}", "process": "{{ if .Workload }}{{ if .Workload.Process }}{{ if .Workload.Process.Thread }}{{ .Workload.Process.Thread.Name }}{{ end }}{{ end }}{{ end }}"}`
	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "test.tmpl")
	outputPath := filepath.Join(tempDir, "test_output.txt")

	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	// Create the output file
	file, err := flags.CreateOutputFile(outputPath)
	require.NoError(t, err)
	defer file.Close() // We close it since we created it

	// Create printer config
	cfg := config.PrinterConfig{
		Kind:    "gotemplate=" + templatePath,
		OutFile: file,
	}

	// Create and initialize the printer
	p, err := printer.New(cfg)
	require.NoError(t, err)

	// Create a sample event
	sampleEvent := trace.Event{
		ProcessName: "test_process",
		EventName:   "test_event",
	}

	// Convert to pb.Event
	pbEvent, err := events.ConvertTraceeEventToProto(sampleEvent)
	require.NoError(t, err)

	// Print an event
	p.Preamble()
	p.Print(pbEvent)
	p.Close() // This should flush the buffer via Sync()

	// Read the file content (file is still open, but Sync() should have flushed data to disk)
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err, "Should be able to read flushed data while file is still open")

	// Verify data was written and flushed
	assert.NotEmpty(t, content, "File should contain data after Sync()")
	assert.Contains(t, string(content), "test_process", "File should contain event data")
	assert.Contains(t, string(content), "test_event", "File should contain event name")
}
