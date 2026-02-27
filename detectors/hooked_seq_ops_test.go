package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestHookedSeqOps_GetDefinition(t *testing.T) {
	detector := &HookedSeqOps{}
	def := detector.GetDefinition()

	assert.Equal(t, "DRV-003", def.ID)
	assert.Len(t, def.Requirements.Events, 2)
	assert.Equal(t, "print_net_seq_ops", def.Requirements.Events[0].Name)
	assert.Equal(t, "do_init_module", def.Requirements.Events[1].Name)

	assert.Len(t, def.Requirements.DataStores, 1)
	assert.Equal(t, datastores.Symbol, def.Requirements.DataStores[0].Name)

	assert.Equal(t, "hooked_seq_ops_detector", def.ProducedEvent.Name)
	assert.Len(t, def.ProducedEvent.Fields, 1)
	assert.Equal(t, "hooked_seq_ops_detector", def.ProducedEvent.Fields[0].Name)
}

func TestHookedSeqOps_Init(t *testing.T) {
	detector := &HookedSeqOps{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestHookedSeqOps_OnEvent_SingleHook(t *testing.T) {
	detector := &HookedSeqOps{}

	// Single hook at tcp4_seq_ops.show (index 0)
	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "malicious_show", Module: "rootkit"},
			},
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}
	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create 24-element array (6 seq_ops * 4 functions each), only first is hooked
	seqOpsArray := make([]uint64, 24)
	seqOpsArray[0] = 0xffffffffc0001000 // tcp4_seq_ops.show hooked

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_print_net_seq_ops,
		Data: []*v1beta1.EventValue{
			{
				Name: "net_seq_ops",
				Value: &v1beta1.EventValue_UInt64Array{
					UInt64Array: &v1beta1.UInt64Array{Value: seqOpsArray},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	// Verify the output has the hooked_seq_ops map
	output := outputEvents[0]
	require.Len(t, output.Data, 1)
	assert.Equal(t, "hooked_seq_ops_detector", output.Data[0].Name)

	// Extract and verify the map
	hookedSeqOps := output.Data[0].GetHookedSeqOps()
	require.NotNil(t, hookedSeqOps)
	require.Len(t, hookedSeqOps.Value, 1)

	tcp4Show, ok := hookedSeqOps.Value["tcp4_seq_ops_show"]
	require.True(t, ok)
	assert.Equal(t, "malicious_show", tcp4Show.SymbolName)
	assert.Equal(t, "rootkit", tcp4Show.ModuleOwner)
}

func TestHookedSeqOps_OnEvent_MultipleHooks(t *testing.T) {
	detector := &HookedSeqOps{}

	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {{Name: "hook_tcp4_show", Module: "rootkit1"}},
			0xffffffffc0002000: {{Name: "hook_tcp4_next", Module: "rootkit1"}},
			0xffffffffc0003000: {{Name: "hook_udp_start", Module: "rootkit2"}},
			0xffffffffc0004000: {{Name: "hook_raw6_stop", Module: "rootkit3"}},
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}
	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Hook at indices: 0 (tcp4.show), 2 (tcp4.next), 9 (udp.start), 23 (raw6.stop)
	seqOpsArray := make([]uint64, 24)
	seqOpsArray[0] = 0xffffffffc0001000  // tcp4_seq_ops.show
	seqOpsArray[2] = 0xffffffffc0002000  // tcp4_seq_ops.next
	seqOpsArray[9] = 0xffffffffc0003000  // udp_seq_ops.start
	seqOpsArray[23] = 0xffffffffc0004000 // raw6_seq_ops.stop

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_print_net_seq_ops,
		Data: []*v1beta1.EventValue{
			{
				Name: "net_seq_ops",
				Value: &v1beta1.EventValue_UInt64Array{
					UInt64Array: &v1beta1.UInt64Array{Value: seqOpsArray},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	hookedSeqOps := outputEvents[0].Data[0].GetHookedSeqOps()
	require.NotNil(t, hookedSeqOps)
	require.Len(t, hookedSeqOps.Value, 4)

	// Verify all four hooks
	assert.Equal(t, "hook_tcp4_show", hookedSeqOps.Value["tcp4_seq_ops_show"].SymbolName)
	assert.Equal(t, "hook_tcp4_next", hookedSeqOps.Value["tcp4_seq_ops_next"].SymbolName)
	assert.Equal(t, "hook_udp_start", hookedSeqOps.Value["udp_seq_ops_start"].SymbolName)
	assert.Equal(t, "hook_raw6_stop", hookedSeqOps.Value["raw6_seq_ops_stop"].SymbolName)
}

func TestHookedSeqOps_OnEvent_NoHooks(t *testing.T) {
	detector := &HookedSeqOps{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// All zeros - no hooks
	seqOpsArray := make([]uint64, 24)

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_print_net_seq_ops,
		Data: []*v1beta1.EventValue{
			{
				Name: "net_seq_ops",
				Value: &v1beta1.EventValue_UInt64Array{
					UInt64Array: &v1beta1.UInt64Array{Value: seqOpsArray},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	// No hooks found means no event produced
	assert.Len(t, outputEvents, 0)
}

func TestHookedSeqOps_OnEvent_EmptyArray(t *testing.T) {
	detector := &HookedSeqOps{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_print_net_seq_ops,
		Data: []*v1beta1.EventValue{
			{
				Name: "net_seq_ops",
				Value: &v1beta1.EventValue_UInt64Array{
					UInt64Array: &v1beta1.UInt64Array{Value: []uint64{}},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Len(t, outputEvents, 0)
}

func TestHookedSeqOps_OnEvent_SymbolNotResolved(t *testing.T) {
	detector := &HookedSeqOps{}

	// Symbol store with no symbols (can't resolve addresses)
	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Hook present but can't be resolved
	seqOpsArray := make([]uint64, 24)
	seqOpsArray[0] = 0xffffffffc0001000

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_print_net_seq_ops,
		Data: []*v1beta1.EventValue{
			{
				Name: "net_seq_ops",
				Value: &v1beta1.EventValue_UInt64Array{
					UInt64Array: &v1beta1.UInt64Array{Value: seqOpsArray},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	// Can't resolve = skip it, so no events produced
	assert.Len(t, outputEvents, 0)
}

func Test_getSeqOpsSymbols(t *testing.T) {
	// Test the indexing math: seqOpsStruct = netSeqOps[i/4], seqOpsFunc = netSeqOpsFuncs[i%4]
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
		{9, "udp_seq_ops", "start"},
		{23, "raw6_seq_ops", "stop"},
	}

	for _, tc := range testCases {
		actualStruct, actualFunc := getSeqOpsSymbols(tc.index)
		assert.Equal(t, tc.expectedStruct, actualStruct, "index %d", tc.index)
		assert.Equal(t, tc.expectedFunc, actualFunc, "index %d", tc.index)
	}

	// Test out of bounds
	struct1, func1 := getSeqOpsSymbols(-1)
	assert.Equal(t, "", struct1)
	assert.Equal(t, "", func1)

	struct2, func2 := getSeqOpsSymbols(100)
	assert.Equal(t, "", struct2)
	assert.Equal(t, "", func2)
}

func TestHookedSeqOps_Close(t *testing.T) {
	detector := &HookedSeqOps{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{}, SymbolStore: symbolStore}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}
