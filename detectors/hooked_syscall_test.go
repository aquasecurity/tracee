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

func TestHookedSyscall_GetDefinition(t *testing.T) {
	detector := &HookedSyscall{}
	def := detector.GetDefinition()

	assert.Equal(t, "DRV-002", def.ID)
	assert.Len(t, def.Requirements.Events, 2)
	assert.Equal(t, "syscall_table_check", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)
	assert.Equal(t, "do_init_module", def.Requirements.Events[1].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[1].Dependency)

	assert.Len(t, def.Requirements.DataStores, 2)
	assert.Equal(t, "symbol", def.Requirements.DataStores[0].Name)
	assert.Equal(t, "syscall", def.Requirements.DataStores[1].Name)

	// Check produced event schema matches original
	assert.Equal(t, "hooked_syscall_detector", def.ProducedEvent.Name)
	require.Len(t, def.ProducedEvent.Fields, 4)
	assert.Equal(t, "syscall", def.ProducedEvent.Fields[0].Name)
	assert.Equal(t, "address", def.ProducedEvent.Fields[1].Name)
	assert.Equal(t, "function", def.ProducedEvent.Fields[2].Name)
	assert.Equal(t, "owner", def.ProducedEvent.Fields[3].Name)

	// Check threat metadata
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_CRITICAL, def.ThreatMetadata.Severity)
}

func TestHookedSyscall_Init(t *testing.T) {
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	syscallStore := &testutil.MockSyscallStore{Syscalls: map[int32]string{}}
	registry := &testutil.MockDataStoreRegistryWithStores{
		MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:           symbolStore,
		SyscallStore:          syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	assert.NotNil(t, detector.reportedHooks)
	assert.NotNil(t, detector.symbolStore)
	assert.NotNil(t, detector.syscallStore)
}

func TestHookedSyscall_OnEvent_SymbolResolved(t *testing.T) {
	// Create detector with mock datastores
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "fake_read", Module: "rootkit"},
			},
		},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			0: "read",
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create input event (syscall_table_check)
	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 0), // read syscall
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0001000),
		},
	}

	// Process event
	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	// Verify output matches original schema and logic
	output := outputEvents[0]
	require.Len(t, output.Data, 4)

	assert.Equal(t, "syscall", output.Data[0].Name)
	syscallName := testutil.GetOutputData(output, "syscall")
	assert.Equal(t, "read", syscallName)

	assert.Equal(t, "address", output.Data[1].Name)
	address := testutil.GetOutputData(output, "address")
	assert.Equal(t, "ffffffffc0001000", address)

	assert.Equal(t, "function", output.Data[2].Name)
	function := testutil.GetOutputData(output, "function")
	assert.Equal(t, "fake_read", function)

	assert.Equal(t, "owner", output.Data[3].Name)
	owner := testutil.GetOutputData(output, "owner")
	assert.Equal(t, "rootkit", owner)
}

func TestHookedSyscall_OnEvent_SymbolNotResolved(t *testing.T) {
	detector := &HookedSyscall{}

	// Symbol store with no symbols for this address
	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			1: "write",
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create input event
	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 1), // write syscall
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0002000),
		},
	}

	// Process event
	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	// When symbol not resolved, should have empty function and owner (matches original)
	output := outputEvents[0]
	require.Len(t, output.Data, 4)

	syscallName := testutil.GetOutputData(output, "syscall")
	assert.Equal(t, "write", syscallName)

	address := testutil.GetOutputData(output, "address")
	assert.Equal(t, "ffffffffc0002000", address)

	function := testutil.GetOutputData(output, "function")
	assert.Equal(t, "", function) // empty function

	owner := testutil.GetOutputData(output, "owner")
	assert.Equal(t, "", owner) // empty owner
}

func TestHookedSyscall_OnEvent_MultipleSymbolsAtSameAddress(t *testing.T) {
	detector := &HookedSyscall{}

	// Multiple symbols at the same address (aliasing)
	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "fake_read_alias1", Module: "rootkit"},
				{Name: "fake_read_alias2", Module: "rootkit"},
			},
		},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			0: "read",
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 0),
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0001000),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	// Should produce one event per symbol (matches original behavior)
	require.Len(t, outputEvents, 2)

	// Verify both events
	func1 := testutil.GetOutputData(outputEvents[0], "function")
	assert.Equal(t, "fake_read_alias1", func1)

	func2 := testutil.GetOutputData(outputEvents[1], "function")
	assert.Equal(t, "fake_read_alias2", func2)
}

func TestHookedSyscall_OnEvent_CacheBehavior(t *testing.T) {
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "fake_read", Module: "rootkit"},
			},
		},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			0: "read",
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 0),
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0001000),
		},
	}

	ctx := context.Background()

	// First occurrence should be reported
	outputEvents1, err := detector.OnEvent(ctx, inputEvent)
	require.NoError(t, err)
	require.Len(t, outputEvents1, 1)

	// Second occurrence with same syscall_id and address should NOT be reported (cached)
	outputEvents2, err := detector.OnEvent(ctx, inputEvent)
	require.NoError(t, err)
	assert.Len(t, outputEvents2, 0) // Cached, no output
}

func TestHookedSyscall_OnEvent_CacheUpdate(t *testing.T) {
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "fake_read_v1", Module: "rootkit"},
			},
			0xffffffffc0002000: {
				{Name: "fake_read_v2", Module: "rootkit"},
			},
		},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			0: "read",
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// First hook at address 1
	event1 := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 0),
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0001000),
		},
	}

	output1, err := detector.OnEvent(ctx, event1)
	require.NoError(t, err)
	require.Len(t, output1, 1)

	func1 := testutil.GetOutputData(output1[0], "function")
	assert.Equal(t, "fake_read_v1", func1)

	// Same syscall now hooked at a different address (cache should update and report)
	event2 := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 0),                        // same syscall
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0002000), // different address
		},
	}

	output2, err := detector.OnEvent(ctx, event2)
	require.NoError(t, err)
	require.Len(t, output2, 1) // Should report the change

	func2 := testutil.GetOutputData(output2[0], "function")
	assert.Equal(t, "fake_read_v2", func2)
}

func TestHookedSyscall_OnEvent_UnknownSyscall(t *testing.T) {
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{
		Symbols: map[uint64][]*datastores.SymbolInfo{
			0xffffffffc0001000: {
				{Name: "fake_unknown", Module: "rootkit"},
			},
		},
	}

	syscallStore := &testutil.MockSyscallStore{
		Syscalls: map[int32]string{
			// Syscall ID 999 not in the map
		},
	}

	registry := &testutil.MockDataStoreRegistryWithStores{MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:  symbolStore,
		SyscallStore: syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_syscall_table_check,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("syscall_id", 999), // unknown syscall
			v1beta1.NewUInt64Value("syscall_address", 0xffffffffc0001000),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)

	// Should have empty syscall name (matches original behavior)
	syscallName := testutil.GetOutputData(outputEvents[0], "syscall")
	assert.Equal(t, "", syscallName)

	function := testutil.GetOutputData(outputEvents[0], "function")
	assert.Equal(t, "fake_unknown", function)
}

func TestHookedSyscall_Close(t *testing.T) {
	detector := &HookedSyscall{}

	symbolStore := &testutil.MockKernelSymbolStore{Symbols: map[uint64][]*datastores.SymbolInfo{}}
	syscallStore := &testutil.MockSyscallStore{Syscalls: map[int32]string{}}
	registry := &testutil.MockDataStoreRegistryWithStores{
		MockDataStoreRegistry: testutil.MockDataStoreRegistry{},
		SymbolStore:           symbolStore,
		SyscallStore:          syscallStore,
	}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: registry,
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}
