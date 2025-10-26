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

// createTestKernelSymbolTable creates a KernelSymbolTable from a string for testing
func createTestKernelSymbolTable(symbolData string) (*symbol.KernelSymbolTable, error) {
	return symbol.NewKernelSymbolTableFromReader(strings.NewReader(symbolData), false, false)
}

func Test_HookedSeqOps_Derive(t *testing.T) {
	tests := []struct {
		name           string
		inputEvent     trace.Event
		symbolData     string
		expectedEvents []trace.Event
		expectedErrors []error
	}{
		{
			name: "single hooked seq_ops - tcp4_seq_ops.show",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "net_seq_ops",
							Type: "[]uint64",
						},
						// 24 addresses: 6 seq_ops structs * 4 function pointers each
						// Only first address (tcp4_seq_ops.show) is hooked (non-zero)
						Value: []uint64{0xffffffffc0001000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			symbolData: "ffffffffc0001000 t malicious_show\trootkit",
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSeqOps),
					EventName: "hooked_seq_ops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_seq_ops",
								Type: "map[string]trace.HookedSymbolData",
							},
							Value: map[string]trace.HookedSymbolData{
								"tcp4_seq_ops_show": {
									SymbolName:  "malicious_show",
									ModuleOwner: "rootkit",
								},
							},
						},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "multiple hooked seq_ops across different structs",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "net_seq_ops",
							Type: "[]uint64",
						},
						// tcp4_seq_ops.show (index 0), tcp4_seq_ops.next (index 2),
						// udp_seq_ops.start (index 9), raw6_seq_ops.stop (index 23)
						Value: []uint64{
							0xffffffffc0001000, 0, 0xffffffffc0002000, 0, // tcp4_seq_ops
							0, 0, 0, 0, // tcp6_seq_ops
							0, 0xffffffffc0003000, 0, 0, // udp_seq_ops (start hooked)
							0, 0, 0, 0, // udp6_seq_ops
							0, 0, 0, 0, // raw_seq_ops
							0, 0, 0, 0xffffffffc0004000, // raw6_seq_ops (stop hooked)
						},
					},
				},
			},
			symbolData: `ffffffffc0001000 t hook_tcp4_show	rootkit1
ffffffffc0002000 t hook_tcp4_next	rootkit1
ffffffffc0003000 t hook_udp_start	rootkit2
ffffffffc0004000 t hook_raw6_stop	rootkit3`,
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSeqOps),
					EventName: "hooked_seq_ops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_seq_ops",
								Type: "map[string]trace.HookedSymbolData",
							},
							Value: map[string]trace.HookedSymbolData{
								"tcp4_seq_ops_show": {
									SymbolName:  "hook_tcp4_show",
									ModuleOwner: "rootkit1",
								},
								"tcp4_seq_ops_next": {
									SymbolName:  "hook_tcp4_next",
									ModuleOwner: "rootkit1",
								},
								"udp_seq_ops_start": {
									SymbolName:  "hook_udp_start",
									ModuleOwner: "rootkit2",
								},
								"raw6_seq_ops_stop": {
									SymbolName:  "hook_raw6_stop",
									ModuleOwner: "rootkit3",
								},
							},
						},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "all seq_ops functions hooked",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "net_seq_ops",
							Type: "[]uint64",
						},
						// All 24 function pointers hooked
						Value: []uint64{
							0xffffffffc0000001, 0xffffffffc0000002, 0xffffffffc0000003, 0xffffffffc0000004, // tcp4
							0xffffffffc0000005, 0xffffffffc0000006, 0xffffffffc0000007, 0xffffffffc0000008, // tcp6
							0xffffffffc0000009, 0xffffffffc000000a, 0xffffffffc000000b, 0xffffffffc000000c, // udp
							0xffffffffc000000d, 0xffffffffc000000e, 0xffffffffc000000f, 0xffffffffc0000010, // udp6
							0xffffffffc0000011, 0xffffffffc0000012, 0xffffffffc0000013, 0xffffffffc0000014, // raw
							0xffffffffc0000015, 0xffffffffc0000016, 0xffffffffc0000017, 0xffffffffc0000018, // raw6
						},
					},
				},
			},
			symbolData: `ffffffffc0000001 t hooked_func	malicious
ffffffffc0000002 t hooked_func	malicious
ffffffffc0000003 t hooked_func	malicious
ffffffffc0000004 t hooked_func	malicious
ffffffffc0000005 t hooked_func	malicious
ffffffffc0000006 t hooked_func	malicious
ffffffffc0000007 t hooked_func	malicious
ffffffffc0000008 t hooked_func	malicious
ffffffffc0000009 t hooked_func	malicious
ffffffffc000000a t hooked_func	malicious
ffffffffc000000b t hooked_func	malicious
ffffffffc000000c t hooked_func	malicious
ffffffffc000000d t hooked_func	malicious
ffffffffc000000e t hooked_func	malicious
ffffffffc000000f t hooked_func	malicious
ffffffffc0000010 t hooked_func	malicious
ffffffffc0000011 t hooked_func	malicious
ffffffffc0000012 t hooked_func	malicious
ffffffffc0000013 t hooked_func	malicious
ffffffffc0000014 t hooked_func	malicious
ffffffffc0000015 t hooked_func	malicious
ffffffffc0000016 t hooked_func	malicious
ffffffffc0000017 t hooked_func	malicious
ffffffffc0000018 t hooked_func	malicious`,
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSeqOps),
					EventName: "hooked_seq_ops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_seq_ops",
								Type: "map[string]trace.HookedSymbolData",
							},
							Value: map[string]trace.HookedSymbolData{
								"tcp4_seq_ops_show":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp4_seq_ops_start": {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp4_seq_ops_next":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp4_seq_ops_stop":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp6_seq_ops_show":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp6_seq_ops_start": {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp6_seq_ops_next":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"tcp6_seq_ops_stop":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp_seq_ops_show":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp_seq_ops_start":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp_seq_ops_next":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp_seq_ops_stop":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp6_seq_ops_show":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp6_seq_ops_start": {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp6_seq_ops_next":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"udp6_seq_ops_stop":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw_seq_ops_show":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw_seq_ops_start":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw_seq_ops_next":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw_seq_ops_stop":   {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw6_seq_ops_show":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw6_seq_ops_start": {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw6_seq_ops_next":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
								"raw6_seq_ops_stop":  {SymbolName: "hooked_func", ModuleOwner: "malicious"},
							},
						},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "no hooks - all addresses are zero",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "net_seq_ops",
							Type: "[]uint64",
						},
						// All zeros mean text segment check passed in kernel, no hooks
						Value: []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			symbolData: "", // No symbols needed
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.HookedSeqOps),
					EventName: "hooked_seq_ops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_seq_ops",
								Type: "map[string]trace.HookedSymbolData",
							},
							Value: map[string]trace.HookedSymbolData{},
						},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "missing net_seq_ops argument",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args:      []trace.Argument{},
			},
			symbolData:     "",
			expectedEvents: nil,
			expectedErrors: []error{},
		},
		{
			name: "empty net_seq_ops array",
			inputEvent: trace.Event{
				EventID:   int(events.PrintNetSeqOps),
				EventName: "print_net_seq_ops",
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "net_seq_ops",
							Type: "[]uint64",
						},
						Value: []uint64{},
					},
				},
			},
			symbolData:     "",
			expectedEvents: nil,
			expectedErrors: []error{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create kernel symbol table from test data
			symbolTable, err := createTestKernelSymbolTable(tt.symbolData)
			if tt.symbolData == "" && err != nil {
				// Empty symbol data might fail, create an empty table
				symbolTable, err = createTestKernelSymbolTable("ffffffff00000000 t dummy\tkernel")
				require.NoError(t, err)
			} else if err != nil {
				t.Fatalf("Failed to create symbol table: %v", err)
			}

			deriveFunction := HookedSeqOps(symbolTable)
			events, errs := deriveFunction(&tt.inputEvent)

			if len(tt.expectedErrors) > 0 {
				assert.NotEmpty(t, errs)
			} else if tt.expectedEvents == nil {
				// Error case - should have no events and possibly errors
				assert.Empty(t, events)
			} else {
				assert.Empty(t, errs)
			}

			if tt.expectedEvents != nil {
				require.Len(t, events, len(tt.expectedEvents))
				for i, expectedEvent := range tt.expectedEvents {
					actualEvent := events[i]
					assert.Equal(t, expectedEvent.EventID, actualEvent.EventID)
					assert.Equal(t, expectedEvent.EventName, actualEvent.EventName)
					require.Len(t, actualEvent.Args, len(expectedEvent.Args))

					// Compare the hooked_seq_ops map
					expectedMap, ok := expectedEvent.Args[0].Value.(map[string]trace.HookedSymbolData)
					require.True(t, ok, "Expected map should be a map[string]trace.HookedSymbolData")
					actualMap, ok := actualEvent.Args[0].Value.(map[string]trace.HookedSymbolData)
					require.True(t, ok, "Actual map should be a map[string]trace.HookedSymbolData")
					assert.Equal(t, expectedMap, actualMap)
				}
			} else {
				assert.Empty(t, events)
			}
		})
	}
}

func Test_HookedSeqOps_getSeqOpsSymbols(t *testing.T) {
	// Test that the indexing math works correctly
	// For an address at index i:
	//   - seqOpsStruct = NetSeqOps[i/4]
	//   - seqOpsFunc = NetSeqOpsFuncs[i%4]

	testCases := []struct {
		index          int
		expectedStruct string
		expectedFunc   string
	}{
		{0, "tcp4_seq_ops", "show"},
		{1, "tcp4_seq_ops", "start"},
		{2, "tcp4_seq_ops", "next"},
		{3, "tcp4_seq_ops", "stop"},
		{4, "tcp6_seq_ops", "show"},
		{5, "tcp6_seq_ops", "start"},
		{6, "tcp6_seq_ops", "next"},
		{7, "tcp6_seq_ops", "stop"},
		{8, "udp_seq_ops", "show"},
		{23, "raw6_seq_ops", "stop"},
	}

	for _, tc := range testCases {
		actualStruct, actualFunc := getSeqOpsSymbols(tc.index)
		assert.Equal(t, tc.expectedStruct, actualStruct, "index %d", tc.index)
		assert.Equal(t, tc.expectedFunc, actualFunc, "index %d", tc.index)
	}
}
