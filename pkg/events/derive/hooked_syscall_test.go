package derive

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/datastores/symbol"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_DetectHookedSyscall_Derive(t *testing.T) {
	tests := []struct {
		name               string
		inputEvents        []trace.Event
		symbolData         string
		expectedEvents     []trace.Event
		expectedErrorCount int
	}{
		{
			name: "single hooked syscall with known symbol",
			inputEvents: []trace.Event{
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_id",
								Type: "int32",
							},
							Value: int32(events.Read),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_address",
								Type: "uint64",
							},
							Value: uint64(0xffffffffc0001000),
						},
					},
				},
			},
			symbolData: "ffffffffc0001000 t fake_read\trootkit",
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSyscall),
					EventName: "hooked_syscall",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall", Type: "string"}, Value: "read"},
						{ArgMeta: trace.ArgMeta{Name: "address", Type: "string"}, Value: "ffffffffc0001000"},
						{ArgMeta: trace.ArgMeta{Name: "function", Type: "string"}, Value: "fake_read"},
						{ArgMeta: trace.ArgMeta{Name: "owner", Type: "string"}, Value: "rootkit"},
					},
				},
			},
			expectedErrorCount: 0,
		},
		{
			name: "hooked syscall with unknown symbol",
			inputEvents: []trace.Event{
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_id",
								Type: "int32",
							},
							Value: int32(events.Write),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_address",
								Type: "uint64",
							},
							Value: uint64(0xffffffffc0002000),
						},
					},
				},
			},
			symbolData: "", // No matching symbol
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSyscall),
					EventName: "hooked_syscall",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall", Type: "string"}, Value: "write"},
						{ArgMeta: trace.ArgMeta{Name: "address", Type: "string"}, Value: "ffffffffc0002000"},
						{ArgMeta: trace.ArgMeta{Name: "function", Type: "string"}, Value: ""},
						{ArgMeta: trace.ArgMeta{Name: "owner", Type: "string"}, Value: ""},
					},
				},
			},
			expectedErrorCount: 0,
		},
		{
			name: "multiple hooked syscalls",
			inputEvents: []trace.Event{
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Open)},
						{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0003000)},
					},
				},
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Close)},
						{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0004000)},
					},
				},
			},
			symbolData: `ffffffffc0003000 t fake_open	rootkit1
ffffffffc0004000 t fake_close	rootkit2`,
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSyscall),
					EventName: "hooked_syscall",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall", Type: "string"}, Value: "open"},
						{ArgMeta: trace.ArgMeta{Name: "address", Type: "string"}, Value: "ffffffffc0003000"},
						{ArgMeta: trace.ArgMeta{Name: "function", Type: "string"}, Value: "fake_open"},
						{ArgMeta: trace.ArgMeta{Name: "owner", Type: "string"}, Value: "rootkit1"},
					},
				},
				{
					EventID:   int(events.HookedSyscall),
					EventName: "hooked_syscall",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "syscall", Type: "string"}, Value: "close"},
						{ArgMeta: trace.ArgMeta{Name: "address", Type: "string"}, Value: "ffffffffc0004000"},
						{ArgMeta: trace.ArgMeta{Name: "function", Type: "string"}, Value: "fake_close"},
						{ArgMeta: trace.ArgMeta{Name: "owner", Type: "string"}, Value: "rootkit2"},
					},
				},
			},
			expectedErrorCount: 0,
		},
		{
			name: "missing syscall_id argument",
			inputEvents: []trace.Event{
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_address",
								Type: "uint64",
							},
							Value: uint64(0xffffffffc0005000),
						},
					},
				},
			},
			symbolData:         "",
			expectedEvents:     nil,
			expectedErrorCount: 1,
		},
		{
			name: "missing syscall_address argument",
			inputEvents: []trace.Event{
				{
					EventID:   int(events.SyscallTableCheck),
					EventName: "syscall_table_check",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "syscall_id",
								Type: "int32",
							},
							Value: int32(events.Read),
						},
					},
				},
			},
			symbolData:         "",
			expectedEvents:     nil,
			expectedErrorCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the LRU cache for each test
			err := resetHookedSyscallForTesting()
			require.NoError(t, err)

			// Create kernel symbol table from test data
			symbolTable, err := createTestKernelSymbolTable(tt.symbolData)
			if tt.symbolData == "" && err != nil {
				// Empty symbol data might fail, create a dummy table
				symbolTable, err = createTestKernelSymbolTable("ffffffff00000000 t dummy\tkernel")
				require.NoError(t, err)
			} else if err != nil {
				t.Fatalf("Failed to create symbol table: %v", err)
			}

			deriveFunction := DetectHookedSyscall(symbolTable)

			var allDerivedEvents []trace.Event
			var allErrors []error

			for _, inputEvent := range tt.inputEvents {
				events, errs := deriveFunction(&inputEvent)
				allDerivedEvents = append(allDerivedEvents, events...)
				allErrors = append(allErrors, errs...)
			}

			assert.Equal(t, tt.expectedErrorCount, len(allErrors))

			if tt.expectedErrorCount > 0 {
				assert.NotEmpty(t, allErrors)
			} else if tt.expectedEvents == nil {
				// Error case - should have no events and possibly errors
				assert.Empty(t, allDerivedEvents, "Expected no events")
			} else {
				assert.Empty(t, allErrors, "Expected no errors")
			}

			if tt.expectedEvents != nil {
				require.Len(t, allDerivedEvents, len(tt.expectedEvents), "Expected %d events", len(tt.expectedEvents))
				for i, expectedEvent := range tt.expectedEvents {
					actualEvent := allDerivedEvents[i]
					assert.Equal(t, expectedEvent.EventID, actualEvent.EventID)
					assert.Equal(t, expectedEvent.EventName, actualEvent.EventName)
					require.Len(t, actualEvent.Args, len(expectedEvent.Args))
					for j, expectedArg := range expectedEvent.Args {
						assert.Equal(t, expectedArg.Value, actualEvent.Args[j].Value)
					}
				}
			} else {
				assert.Empty(t, allDerivedEvents)
			}
		})
	}
}

func Test_DetectHookedSyscall_CacheBehavior(t *testing.T) {
	// Initialize the LRU cache
	err := resetHookedSyscallForTesting()
	require.NoError(t, err)

	// Create a test symbol table
	symbolData := "ffffffffc0001000 t fake_read\trootkit"
	symbolTable, err := createTestKernelSymbolTable(symbolData)
	require.NoError(t, err)

	deriveFunction := DetectHookedSyscall(symbolTable)

	// First occurrence should be reported
	event1 := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0001000)},
		},
	}

	events1, errs1 := deriveFunction(&event1)
	assert.Empty(t, errs1)
	assert.Len(t, events1, 1, "First occurrence should be reported")
	assert.Equal(t, "read", events1[0].Args[0].Value)

	// Second occurrence with same syscall_id and address should NOT be reported (cached)
	events2, errs2 := deriveFunction(&event1)
	assert.Empty(t, errs2)
	assert.Empty(t, events2, "Second occurrence should not be reported (cached)")

	// Same syscall_id but different address should be reported
	event2 := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0002000)},
		},
	}

	events3, errs3 := deriveFunction(&event2)
	assert.Empty(t, errs3)
	assert.Len(t, events3, 1, "Different address should be reported")
}

func Test_DetectHookedSyscall_CacheUpdate(t *testing.T) {
	// Initialize the LRU cache
	err := resetHookedSyscallForTesting()
	require.NoError(t, err)

	// Create a test symbol table
	symbolData := `ffffffffc0001000 t fake_read_v1	rootkit
ffffffffc0002000 t fake_read_v2	rootkit`
	symbolTable, err := createTestKernelSymbolTable(symbolData)
	require.NoError(t, err)

	deriveFunction := DetectHookedSyscall(symbolTable)

	// First hook at address 0xffffffffc0001000
	event1 := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0001000)},
		},
	}

	events1, errs1 := deriveFunction(&event1)
	assert.Empty(t, errs1)
	assert.Len(t, events1, 1)

	// Hook changed to different address - should be reported (cache is updated)
	event2 := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0002000)},
		},
	}

	events2, errs2 := deriveFunction(&event2)
	assert.Empty(t, errs2)
	assert.Len(t, events2, 1, "Changed address should be reported")

	// Verify the new address is now cached
	event3 := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0002000)},
		},
	}

	events3, errs3 := deriveFunction(&event3)
	assert.Empty(t, errs3)
	assert.Empty(t, events3, "Same new address should not be reported again")
}

func Test_DetectHookedSyscall_ConvertToSyscallName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		syscallID    int32
		expectedName string
	}{
		{int32(events.Read), "read"},
		{int32(events.Write), "write"},
		{int32(events.Open), "open"},
		{int32(events.Close), "close"},
		{int32(events.Execve), "execve"},
		{int32(9999), ""}, // Invalid syscall ID
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			name := convertToSyscallName(tt.syscallID)
			assert.Equal(t, tt.expectedName, name)
		})
	}
}

func Test_DetectHookedSyscall_MultipleSymbolsAtSameAddress(t *testing.T) {
	// Initialize the LRU cache
	err := resetHookedSyscallForTesting()
	require.NoError(t, err)

	// Create a symbol table with multiple symbols at the same address (aliasing)
	symbolData := `ffffffffc0001000 t fake_read_alias1	rootkit
ffffffffc0001000 t fake_read_alias2	rootkit`
	symbolTable, err := symbol.NewKernelSymbolTableFromReader(strings.NewReader(symbolData), false, false)
	require.NoError(t, err)

	deriveFunction := DetectHookedSyscall(symbolTable)

	event := trace.Event{
		EventID:   int(events.SyscallTableCheck),
		EventName: "syscall_table_check",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "syscall_id", Type: "int32"}, Value: int32(events.Read)},
			{ArgMeta: trace.ArgMeta{Name: "syscall_address", Type: "uint64"}, Value: uint64(0xffffffffc0001000)},
		},
	}

	derivedEvents, errs := deriveFunction(&event)
	assert.Empty(t, errs)
	// Should generate one event per symbol at that address
	assert.Len(t, derivedEvents, 2, "Should report all symbols at the same address")
}

func TestInitHookedSyscall(t *testing.T) {
	// Test that initialization succeeds
	err := InitHookedSyscall()
	assert.NoError(t, err)

	// Test that multiple initializations don't fail
	err = InitHookedSyscall()
	assert.NoError(t, err)
}
