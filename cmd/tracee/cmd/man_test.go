package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestShowEventDocumentation(t *testing.T) {
	// Use the shared signature loading from man.go
	ensureSignaturesLoaded()

	testCases := []struct {
		name          string
		eventName     string
		expectedError error
		shouldFind    bool
		eventType     string
	}{
		{
			name:          "syscall event - openat",
			eventName:     "openat",
			expectedError: nil,
			shouldFind:    true,
			eventType:     "syscall",
		},
		{
			name:          "built-in event - sched_process_exec",
			eventName:     "sched_process_exec",
			expectedError: nil,
			shouldFind:    true,
			eventType:     "builtin",
		},
		{
			name:          "non-existent event",
			eventName:     "non_existent_event_12345",
			expectedError: nil,
			shouldFind:    false,
			eventType:     "",
		},
	}

	// Add signature event test case if signatures are available
	if signaturesLoaded {
		testCases = append(testCases, struct {
			name          string
			eventName     string
			expectedError error
			shouldFind    bool
			eventType     string
		}{
			name:          "signature event - dropped_executable",
			eventName:     "dropped_executable",
			expectedError: nil,
			shouldFind:    true,
			eventType:     "signature",
		})
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Test if the event can be found
			eventID, found := events.Core.GetDefinitionIDByName(tc.eventName)

			if tc.shouldFind {
				assert.True(t, found, "Event %s should be found", tc.eventName)
				assert.NotEqual(t, events.Undefined, eventID, "Event ID should not be undefined")

				// Get the definition and check its type
				definition := events.Core.GetDefinitionByID(eventID)

				switch tc.eventType {
				case "syscall":
					assert.True(t, definition.IsSyscall(), "Event %s should be a syscall", tc.eventName)
				case "signature":
					assert.True(t, definition.IsSignature(), "Event %s should be a signature", tc.eventName)
				case "builtin":
					assert.False(t, definition.IsSyscall(), "Event %s should not be a syscall", tc.eventName)
					assert.False(t, definition.IsSignature(), "Event %s should not be a signature", tc.eventName)
				}

				// Test that the event has a name and description
				assert.NotEmpty(t, definition.GetName(), "Event should have a name")
				// Note: Some events might have empty descriptions, so we don't assert on that
			} else {
				assert.False(t, found, "Event %s should not be found", tc.eventName)
			}

			// Test the actual showEventDocumentation function by capturing output
			output := captureOutput(func() {
				err := showEventDocumentation(tc.eventName)
				assert.Equal(t, tc.expectedError, err, "showEventDocumentation should return expected error")
			})

			// Verify output contains expected content for found events
			if tc.shouldFind {
				assert.NotEmpty(t, output, "Should produce output for found events")
				if tc.eventType == "syscall" {
					assert.Contains(t, output, "Type: System call", "Syscall events should show correct type")
				}
			} else {
				assert.Contains(t, output, "not found", "Should show 'not found' message for missing events")
			}
		})
	}
}

func TestShowEventDocumentationOutput(t *testing.T) {
	// Use the shared signature loading from man.go
	ensureSignaturesLoaded()

	// Test cases for events that should always be available
	alwaysAvailableTests := []struct {
		name           string
		eventName      string
		expectedOutput []string
	}{
		{
			name:      "syscall event output format",
			eventName: "openat",
			expectedOutput: []string{
				"Event: openat",
				"Type: System call",
				"man 2 openat",
			},
		},
		{
			name:      "non-existent event output",
			eventName: "non_existent_event_12345",
			expectedOutput: []string{
				"not found",
				"tracee list",
			},
		},
	}

	for _, tc := range alwaysAvailableTests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			output := captureOutput(func() {
				err := showEventDocumentation(tc.eventName)
				assert.NoError(t, err, "showEventDocumentation should not return error")
			})

			for _, expected := range tc.expectedOutput {
				assert.Contains(t, output, expected, "Output should contain expected text: %s", expected)
			}
		})
	}

	// Test signature events only if signatures are available
	if signaturesLoaded {
		t.Run("signature event output format", func(t *testing.T) {
			eventName := "dropped_executable"
			expectedOutput := []string{
				"TRACEE-DROPPED-EXECUTABLE",
			}

			_, found := events.Core.GetDefinitionIDByName(eventName)
			if !found {
				t.Skip("Signature event not available in test environment")
				return
			}

			output := captureOutput(func() {
				err := showEventDocumentation(eventName)
				assert.NoError(t, err, "showEventDocumentation should not return error")
			})

			for _, expected := range expectedOutput {
				assert.Contains(t, output, expected, "Output should contain expected text: %s", expected)
			}
		})
	} else {
		t.Run("signature event not available", func(t *testing.T) {
			eventName := "dropped_executable"
			output := captureOutput(func() {
				err := showEventDocumentation(eventName)
				assert.NoError(t, err, "showEventDocumentation should not return error")
			})

			assert.Contains(t, output, "not found", "Should show 'not found' for unavailable signature events")
		})
	}
}

func TestEventTypesClassification(t *testing.T) {
	// Use the shared signature loading from man.go
	ensureSignaturesLoaded()

	testCases := []struct {
		name      string
		eventName string
		checkFunc func(events.Definition) bool
		expected  bool
	}{
		{
			name:      "openat is syscall",
			eventName: "openat",
			checkFunc: func(d events.Definition) bool { return d.IsSyscall() },
			expected:  true,
		},
		{
			name:      "sched_process_exec is not syscall",
			eventName: "sched_process_exec",
			checkFunc: func(d events.Definition) bool { return d.IsSyscall() },
			expected:  false,
		},
		{
			name:      "sched_process_exec is not signature",
			eventName: "sched_process_exec",
			checkFunc: func(d events.Definition) bool { return d.IsSignature() },
			expected:  false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eventID, found := events.Core.GetDefinitionIDByName(tc.eventName)
			require.True(t, found, "Event %s should be found", tc.eventName)

			definition := events.Core.GetDefinitionByID(eventID)
			result := tc.checkFunc(definition)
			assert.Equal(t, tc.expected, result, "Event %s classification check failed", tc.eventName)
		})
	}
}

func TestSignatureEventsAvailableAfterLoading(t *testing.T) {
	// Use the shared signature loading from man.go
	ensureSignaturesLoaded()

	if !signaturesLoaded {
		t.Skip("Skipping signature test - no signatures available in test environment")
		return
	}

	// Test at least one signature event if available
	signatureFound := false
	for _, sig := range loadedSignatures {
		metadata, err := sig.GetMetadata()
		if err != nil {
			continue
		}

		eventID, found := events.Core.GetDefinitionIDByName(metadata.EventName)
		if found {
			definition := events.Core.GetDefinitionByID(eventID)
			assert.True(t, definition.IsSignature(), "Event %s should be classified as signature", metadata.EventName)
			assert.NotEmpty(t, definition.GetName(), "Event %s should have a name", metadata.EventName)
			signatureFound = true
			break // Test at least one signature event
		}
	}

	if !signatureFound {
		t.Skip("No signature events found to test")
	}
}

// TestManCommandIntegration tests the man command functionality with signature loading
func TestManCommandIntegration(t *testing.T) {
	// Use the shared signature loading from man.go
	ensureSignaturesLoaded()

	// Test cases that should always work (built-in events)
	builtInTests := []struct {
		name      string
		eventName string
		eventType string
	}{
		{"syscall event", "openat", "syscall"},
		{"built-in event", "sched_process_exec", "builtin"},
		{"built-in event", "security_file_open", "builtin"},
	}

	for _, tc := range builtInTests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eventID, found := events.Core.GetDefinitionIDByName(tc.eventName)
			assert.True(t, found, "Built-in event %s should always be available", tc.eventName)

			if found {
				definition := events.Core.GetDefinitionByID(eventID)
				assert.NotEmpty(t, definition.GetName(), "Event should have a name")

				// Test the man function doesn't error and captures output properly
				output := captureOutput(func() {
					err := showEventDocumentation(tc.eventName)
					assert.NoError(t, err, "showEventDocumentation should work for built-in events")
				})
				assert.NotEmpty(t, output, "Should produce documentation output")
			}
		})
	}

	// Test signature events if available
	if signaturesLoaded && len(loadedSignatures) > 0 {
		t.Run("signature event - first available", func(t *testing.T) {
			// Find first available signature event
			for _, sig := range loadedSignatures {
				metadata, err := sig.GetMetadata()
				if err != nil {
					continue
				}

				eventID, found := events.Core.GetDefinitionIDByName(metadata.EventName)
				if found {
					definition := events.Core.GetDefinitionByID(eventID)
					assert.True(t, definition.IsSignature(), "Event should be classified as signature")
					assert.NotEmpty(t, definition.GetName(), "Event should have a name")

					// Test the man function works for signature events
					output := captureOutput(func() {
						err := showEventDocumentation(metadata.EventName)
						assert.NoError(t, err, "showEventDocumentation should work for signature events")
					})
					assert.NotEmpty(t, output, "Should produce documentation output for signature events")
					break // Test one signature event
				}
			}
		})
	}
}

// captureOutput captures stdout during function execution
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic("Failed to create pipe for test output capture: " + err.Error())
	}
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err != nil {
		panic("Failed to read captured output: " + err.Error())
	}
	return buf.String()
}

// TestEventDefinitionRequirements tests that event definitions meet basic requirements
func TestEventDefinitionRequirements(t *testing.T) {
	allDefinitions := events.Core.GetDefinitions()

	// Ensure we have some core events
	assert.Greater(t, len(allDefinitions), 10, "Should have at least some core events")

	// Test a few key events exist
	keyEvents := []string{"openat", "execve", "close", "read", "write"}

	for _, eventName := range keyEvents {
		t.Run("event_"+eventName, func(t *testing.T) {
			eventID, found := events.Core.GetDefinitionIDByName(eventName)
			assert.True(t, found, "Key event %s should be available", eventName)

			if found {
				definition := events.Core.GetDefinitionByID(eventID)
				assert.Equal(t, eventName, definition.GetName(), "Event name should match")
				assert.NotEqual(t, events.Undefined, definition.GetID(), "Event should have valid ID")
			}
		})
	}
}
