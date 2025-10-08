package derive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_ProcessExecuteFailed_Derive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		inputEvents    []trace.Event
		expectedEvents []trace.Event
		expectedErrors []error
	}{
		{
			name: "successful derivation - base event first, then finish event",
			inputEvents: []trace.Event{
				// ProcessExecuteFailedInternal event (base event)
				{
					EventID:       int(events.ProcessExecuteFailedInternal),
					EventName:     "process_execute_failed_internal",
					HostProcessID: 1234,
					ProcessName:   "bash",
					HostName:      "test-host",
					Timestamp:     1000,
					Container: trace.Container{
						ID: "test-container",
					},
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/nonexistent"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: "/bin/nonexistent"},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(2049)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(123456)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(1609459200)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(33261)},
						{ArgMeta: trace.ArgMeta{Name: "interpreter_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "stdin_type", Type: "uint16"}, Value: uint16(1)},
						{ArgMeta: trace.ArgMeta{Name: "stdin_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "kernel_invoked", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/nonexistent"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"PATH=/usr/bin"}},
					},
				},
				// ExecuteFinished event (finish event with failure)
				{
					EventID:       int(events.ExecuteFinished),
					EventName:     "execute_finished",
					HostProcessID: 1234,
					Timestamp:     2000,
					ReturnValue:   -2, // ENOENT
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/nonexistent"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/nonexistent", "-l"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"PATH=/usr/bin", "HOME=/root"}},
					},
				},
			},
			expectedEvents: []trace.Event{
				{
					EventID:       int(events.ProcessExecuteFailed),
					EventName:     "process_execute_failed",
					HostProcessID: 1234,
					ProcessName:   "bash",
					HostName:      "test-host",
					Timestamp:     2000,
					ReturnValue:   -2,
					Container: trace.Container{
						ID: "test-container",
					},
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/nonexistent"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: "/bin/nonexistent"},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(2049)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(123456)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(1609459200)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(33261)},
						{ArgMeta: trace.ArgMeta{Name: "interpreter_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "stdin_type", Type: "uint16"}, Value: uint16(1)},
						{ArgMeta: trace.ArgMeta{Name: "stdin_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "kernel_invoked", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/nonexistent", "-l"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"PATH=/usr/bin", "HOME=/root"}},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "out of order - finish event before base event",
			inputEvents: []trace.Event{
				// ExecuteFinished event arrives first
				{
					EventID:       int(events.ExecuteFinished),
					EventName:     "execute_finished",
					HostProcessID: 5678,
					Timestamp:     2000,
					ReturnValue:   -13, // EACCES
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/restricted"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/restricted"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{}},
					},
				},
			},
			// Should derive even without base event, using finish event data
			expectedEvents: []trace.Event{
				{
					EventID:       int(events.ProcessExecuteFailed),
					EventName:     "process_execute_failed",
					HostProcessID: 5678,
					Timestamp:     2000,
					ReturnValue:   -13,
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/restricted"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/restricted"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{}},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "successful execution - should not derive",
			inputEvents: []trace.Event{
				// ProcessExecuteFailedInternal event
				{
					EventID:       int(events.ProcessExecuteFailedInternal),
					EventName:     "process_execute_failed_internal",
					HostProcessID: 9999,
					ProcessName:   "bash",
					Timestamp:     1000,
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/ls"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: "/bin/ls"},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(2049)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(654321)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(1609459200)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(33261)},
						{ArgMeta: trace.ArgMeta{Name: "interpreter_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "stdin_type", Type: "uint16"}, Value: uint16(1)},
						{ArgMeta: trace.ArgMeta{Name: "stdin_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "kernel_invoked", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/ls"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"PATH=/usr/bin"}},
					},
				},
				// ExecuteFinished with success (returnValue = 0)
				{
					EventID:       int(events.ExecuteFinished),
					EventName:     "execute_finished",
					HostProcessID: 9999,
					Timestamp:     2000,
					ReturnValue:   0, // Success
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/bin/ls"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(0)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/bin/ls", "-l"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"PATH=/usr/bin"}},
					},
				},
			},
			expectedEvents: nil, // No event should be derived for successful execution
			expectedErrors: nil,
		},
		{
			name: "base event only - should not derive yet",
			inputEvents: []trace.Event{
				{
					EventID:       int(events.ProcessExecuteFailedInternal),
					EventName:     "process_execute_failed_internal",
					HostProcessID: 3333,
					ProcessName:   "sh",
					Timestamp:     1000,
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
						{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/usr/bin/app"},
						{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: "/usr/bin/app"},
						{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(2049)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(111111)},
						{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(1609459200)},
						{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(33261)},
						{ArgMeta: trace.ArgMeta{Name: "interpreter_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "stdin_type", Type: "uint16"}, Value: uint16(1)},
						{ArgMeta: trace.ArgMeta{Name: "stdin_path", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "kernel_invoked", Type: "int32"}, Value: int32(0)},
						{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/usr/bin/app"}},
						{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{}},
					},
				},
			},
			expectedEvents: nil, // Base event should be cached, no derivation yet
			expectedErrors: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			generator, err := InitProcessExecuteFailedGenerator()
			require.NoError(t, err)

			deriveFunction := generator.ProcessExecuteFailed()

			var allDerivedEvents []trace.Event
			var allErrors []error

			for _, inputEvent := range tt.inputEvents {
				events, errs := deriveFunction(&inputEvent)
				allDerivedEvents = append(allDerivedEvents, events...)
				allErrors = append(allErrors, errs...)
			}

			if tt.expectedErrors != nil {
				assert.Equal(t, tt.expectedErrors, allErrors)
			} else {
				assert.Empty(t, allErrors)
			}

			if tt.expectedEvents != nil {
				require.Len(t, allDerivedEvents, len(tt.expectedEvents))
				for i, expectedEvent := range tt.expectedEvents {
					actualEvent := allDerivedEvents[i]
					assert.Equal(t, expectedEvent.EventID, actualEvent.EventID)
					assert.Equal(t, expectedEvent.EventName, actualEvent.EventName)
					assert.Equal(t, expectedEvent.HostProcessID, actualEvent.HostProcessID)
					assert.Equal(t, expectedEvent.Timestamp, actualEvent.Timestamp)
					assert.Equal(t, expectedEvent.ReturnValue, actualEvent.ReturnValue)
					assert.Equal(t, expectedEvent.ProcessName, actualEvent.ProcessName)
					assert.Equal(t, expectedEvent.HostName, actualEvent.HostName)
					assert.Equal(t, expectedEvent.Container, actualEvent.Container)
					require.Len(t, actualEvent.Args, len(expectedEvent.Args))
					for j, expectedArg := range expectedEvent.Args {
						assert.Equal(t, expectedArg, actualEvent.Args[j])
					}
				}
			} else {
				assert.Empty(t, allDerivedEvents)
			}
		})
	}
}

func Test_ProcessExecuteFailed_Init(t *testing.T) {
	t.Parallel()

	generator, err := InitProcessExecuteFailedGenerator()
	require.NoError(t, err)
	assert.NotNil(t, generator.baseEvents)
	assert.Equal(t, events.ProcessExecuteFailed, events.ID(generator.deriveBase.ID))
}

func Test_ProcessExecuteFailed_Caching(t *testing.T) {
	t.Parallel()

	generator, err := InitProcessExecuteFailedGenerator()
	require.NoError(t, err)

	deriveFunction := generator.ProcessExecuteFailed()

	// Send base event for PID 1111
	baseEvent := trace.Event{
		EventID:       int(events.ProcessExecuteFailedInternal),
		EventName:     "process_execute_failed_internal",
		HostProcessID: 1111,
		ProcessName:   "test-process",
		Timestamp:     1000,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
			{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/test/path"},
			{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: "/test/path"},
			{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(2049)},
			{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(999999)},
			{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(1609459200)},
			{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(33261)},
			{ArgMeta: trace.ArgMeta{Name: "interpreter_path", Type: "string"}, Value: ""},
			{ArgMeta: trace.ArgMeta{Name: "stdin_type", Type: "uint16"}, Value: uint16(1)},
			{ArgMeta: trace.ArgMeta{Name: "stdin_path", Type: "string"}, Value: ""},
			{ArgMeta: trace.ArgMeta{Name: "kernel_invoked", Type: "int32"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/test/path"}},
			{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{}},
		},
	}

	traceEvents, errs := deriveFunction(&baseEvent)
	assert.Empty(t, errs)
	assert.Empty(t, traceEvents) // Base event should be cached, no derivation yet

	// Verify base event is in cache
	cachedEvent, ok := generator.baseEvents.Get(1111)
	require.True(t, ok, "Base event should be cached by HostProcessID")
	assert.Equal(t, "test-process", cachedEvent.ProcessName)

	// Send finish event with failure
	finishEvent := trace.Event{
		EventID:       int(events.ExecuteFinished),
		EventName:     "execute_finished",
		HostProcessID: 1111,
		Timestamp:     2000,
		ReturnValue:   -1,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int32"}, Value: int32(-100)},
			{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int32"}, Value: int32(0)},
			{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/test/path"},
			{ArgMeta: trace.ArgMeta{Name: "binary.path", Type: "string"}, Value: ""},
			{ArgMeta: trace.ArgMeta{Name: "binary.device_id", Type: "uint32"}, Value: uint32(0)},
			{ArgMeta: trace.ArgMeta{Name: "binary.inode_number", Type: "uint64"}, Value: uint64(0)},
			{ArgMeta: trace.ArgMeta{Name: "binary.ctime", Type: "uint64"}, Value: uint64(0)},
			{ArgMeta: trace.ArgMeta{Name: "binary.inode_mode", Type: "uint16"}, Value: uint16(0)},
			{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"/test/path", "--flag"}},
			{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"VAR=value"}},
		},
	}

	derivedEvents, errs := deriveFunction(&finishEvent)
	assert.Empty(t, errs)
	require.Len(t, derivedEvents, 1)

	// Verify derived event has combined data from both events
	derivedEvent := derivedEvents[0]
	assert.Equal(t, int(events.ProcessExecuteFailed), derivedEvent.EventID)
	assert.Equal(t, "process_execute_failed", derivedEvent.EventName)
	assert.Equal(t, 1111, derivedEvent.HostProcessID)
	assert.Equal(t, "test-process", derivedEvent.ProcessName) // From base event
	assert.Equal(t, 2000, derivedEvent.Timestamp)             // From finish event
	assert.Equal(t, -1, derivedEvent.ReturnValue)             // From finish event

	// Verify cache is cleaned up after derivation
	_, ok = generator.baseEvents.Get(1111)
	assert.False(t, ok, "Base event should be removed from cache after derivation")
}
