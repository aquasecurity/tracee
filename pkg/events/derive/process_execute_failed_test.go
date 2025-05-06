package derive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestProcessExecuteFailed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		inputEvent     trace.Event
		expectedEvents []trace.Event
		expectedErrors []error
	}{
		{
			name: "successful derivation",
			inputEvent: trace.Event{
				EventID:     int(events.SchedProcessExec),
				ReturnValue: -1,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
							Type: "const char*",
						},
						Value: "/bin/nonexistent",
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "argv",
							Type: "const char**",
						},
						Value: []string{"/bin/nonexistent", "-l"},
					},
				},
				ProcessName: "bash",
				HostName:    "test-host",
				Container: trace.Container{
					ID: "test-container",
				},
			},
			expectedEvents: []trace.Event{
				{
					EventName: "process_execute_failed",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
								Type: "const char*",
							},
							Value: "/bin/nonexistent",
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
								Type: "const char**",
							},
							Value: []string{"/bin/nonexistent", "-l"},
						},
					},
					ProcessName: "bash",
					HostName:    "test-host",
					Container: trace.Container{
						ID: "test-container",
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "successful execution - should not derive",
			inputEvent: trace.Event{
				EventID:     int(events.SchedProcessExec),
				ReturnValue: 0,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
							Type: "const char*",
						},
						Value: "/bin/ls",
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "argv",
							Type: "const char**",
						},
						Value: []string{"/bin/ls", "-l"},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: nil,
		},
		{
			name: "missing pathname argument",
			inputEvent: trace.Event{
				EventID:     int(events.SchedProcessExec),
				ReturnValue: -1,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "argv",
							Type: "const char**",
						},
						Value: []string{"/bin/nonexistent", "-l"},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{errMissingPathnameArg},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			generator, err := InitProcessExecuteFailedGenerator()
			require.NoError(t, err)

			deriveFunction := generator.ProcessExecuteFailed()
			events, errs := deriveFunction(tt.inputEvent)

			if tt.expectedErrors != nil {
				assert.Equal(t, tt.expectedErrors, errs)
			} else {
				assert.Empty(t, errs)
			}

			if tt.expectedEvents != nil {
				assert.Equal(t, tt.expectedEvents, events)
			} else {
				assert.Empty(t, events)
			}
		})
	}
}

func TestInitProcessExecuteFailedGenerator(t *testing.T) {
	t.Parallel()

	generator, err := InitProcessExecuteFailedGenerator()
	require.NoError(t, err)
	assert.NotNil(t, generator.baseEvents)
	assert.Equal(t, events.ProcessExecuteFailed, generator.deriveBase.id)
}
