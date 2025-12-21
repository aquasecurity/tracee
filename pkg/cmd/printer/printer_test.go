package printer_test

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/streams"
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
	cfg := config.Destination{
		Type:   "file",
		Format: "gotemplate=" + templatePath,
		File:   buf,
	}

	// Create and initialize the printer
	p, err := printer.New([]config.Destination{cfg})
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
		name   string
		format string
		typ    string
	}{
		{
			name:   "json printer",
			format: "json",
			typ:    "file",
		},
		{
			name:   "table printer",
			format: "table",
			typ:    "file",
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
			cfg := config.Destination{
				Type:   tc.typ,
				Format: tc.format,
				File:   file,
			}

			// Create and initialize the printer
			p, err := printer.New([]config.Destination{cfg})
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
	cfg := config.Destination{
		Type:   "file",
		Format: "gotemplate=" + templatePath,
		File:   file,
	}

	// Create and initialize the printer
	p, err := printer.New([]config.Destination{cfg})
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

func TestPrinterFromStream(t *testing.T) {
	t.Parallel()

	sm := streams.NewStreamsManager()
	stream := sm.Subscribe(policy.PolicyAll, map[int32]struct{}{}, config.StreamBuffer{})
	outPath := path.Join(t.TempDir(), "file1")

	file, err := flags.CreateOutputFile(outPath)
	require.NoError(t, err)
	defer file.Close()

	destination := config.Destination{
		Type:   "file",
		Format: "json",
		Path:   outPath,
		File:   file,
	}

	p, err := printer.New([]config.Destination{destination})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.FromStream(ctx, stream)
	}()

	pbEvent, err := events.ConvertTraceeEventToProto(trace.Event{
		ProcessName:         "process_from_stream",
		EventName:           "event_from_stream",
		MatchedPoliciesUser: 0b1,
	})
	require.NoError(t, err)

	sm.Publish(t.Context(), pbEvent, 0b1)

	time.Sleep(time.Millisecond * 10)

	cancel()
	wg.Wait() // Wait for goroutine to finish before closing
	p.Close()
	sm.Close()

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)

	assert.NotEmpty(t, content, "file must not be empty")
	assert.Contains(t, string(content), "process_from_stream", "file must contain the pushed process name")
	assert.Contains(t, string(content), "event_from_stream", "file must contain the pushed event name")
}

func TestPrinterCreation(t *testing.T) {
	t.Parallel()

	templateFilePath := path.Join(t.TempDir(), "template1.tpl")
	file, err := flags.CreateOutputFile(templateFilePath)
	require.NoError(t, err)
	file.Close() // close it immediately, we don't need to use it here

	testCases := []struct {
		testName      string
		destinations  []config.Destination
		expectedKind  string
		expectedError string
	}{
		{
			testName: "table_printer_creation_error_no_file",
			destinations: []config.Destination{
				{
					Type:   "file",
					Format: "table",
					Path:   "stdout",
				},
			},
			expectedError: "out file is not set",
		},
		{
			testName: "table_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "file",
					Format: "table",
					Path:   "stdout",
					File:   os.Stdout,
				},
			},
			expectedKind: "table",
		},
		{
			testName: "table_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "file",
					Format: "table-verbose",
					Path:   "stdout",
					File:   os.Stdout,
				},
			},
			expectedKind: "table",
		},
		{
			testName: "json_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "file",
					Format: "json",
					Path:   "stdout",
					File:   os.Stdout,
				},
			},
			expectedKind: "json",
		},
		{
			testName: "template_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "file",
					Format: "gotemplate=" + templateFilePath,
					Path:   "stdout",
					File:   os.Stdout,
				},
			},
			expectedKind: "template",
		},
		{
			testName: "webhook_json_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "webhook",
					Format: "json",
					Url:    "http://1.1.1.1/webhook",
				},
			},
			expectedKind: "webhook",
		},
		{
			testName: "webhook_template_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "webhook",
					Format: "gotemplate=" + templateFilePath,
					Url:    "http://1.1.1.1/webhook",
				},
			},
			expectedKind: "webhook",
		},
		{
			testName: "forward_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "forward",
					Format: "json",
					Url:    "udp://1.1.1.1/fluent",
				},
			},
			expectedKind: "forward",
		},
		{
			testName: "ignore_printer_creation",
			destinations: []config.Destination{
				{
					Type: "ignore",
				},
			},
			expectedKind: "ignore",
		},
		{
			testName: "broadcast_printer_creation",
			destinations: []config.Destination{
				{
					Type:   "forward",
					Format: "json",
					Url:    "tcp://1.1.1.1/fluent",
				},
				{
					Type:   "webhook",
					Format: "json",
					Url:    "http://1.1.1.1/fluent",
				},
			},
			expectedKind: "broadcast",
		},
		{
			testName:      "broadcast_printer_creation_empty_destination_error",
			destinations:  []config.Destination{},
			expectedError: "destinations can't be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			printer, err := printer.New(tc.destinations)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedKind, printer.Kind())
		})
	}

}
