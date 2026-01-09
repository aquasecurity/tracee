package detectors

import (
	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// Test Helpers for Detector Testing
//
// This file provides common mock implementations for testing detectors:
//
// Basic Mocks (no-op implementations):
//   - mockLogger: Minimal logger that discards all output
//   - mockDataStoreRegistry: Returns nil for all datastore types
//
// Functional Mocks (configurable test doubles):
//   - mockKernelSymbolStore: Symbol resolution with configurable symbol map
//   - mockSyscallStore: Syscall ID/name mapping with configurable syscall map
//   - mockDataStoreRegistryWithStores: Registry that provides specific store implementations
//
// Helper Functions:
//   - getOutputData: Extracts string values from DetectorOutput for test assertions
//
// Usage:
//   - Use basic mocks (mockLogger, mockDataStoreRegistry) for detectors that don't need datastore access
//   - Use functional mocks (mockKernelSymbolStore, mockSyscallStore) for detectors requiring symbol/syscall lookups
//   - Implement custom mocks for detectors with complex datastore requirements

// mockLogger for testing - implements detection.Logger.
// All logging methods are no-ops, discarding output for test clarity.
type mockLogger struct{}

// Debugw discards debug log messages.
func (m *mockLogger) Debugw(msg string, keysAndValues ...interface{}) {}

// Infow discards info log messages.
func (m *mockLogger) Infow(msg string, keysAndValues ...interface{}) {}

// Warnw discards warning log messages.
func (m *mockLogger) Warnw(msg string, keysAndValues ...interface{}) {}

// Errorw discards error log messages.
func (m *mockLogger) Errorw(msg string, keysAndValues ...interface{}) {}

// mockDataStoreRegistry for testing - implements datastores.Registry.
// All methods return nil or empty values, suitable for tests where datastores aren't needed.
type mockDataStoreRegistry struct{}

// KernelSymbols returns nil (no symbol store available).
func (m *mockDataStoreRegistry) KernelSymbols() datastores.KernelSymbolStore { return nil }

// Containers returns nil (no container store available).
func (m *mockDataStoreRegistry) Containers() datastores.ContainerStore { return nil }

// Processes returns nil (no process store available).
func (m *mockDataStoreRegistry) Processes() datastores.ProcessStore { return nil }

// DNS returns nil (no DNS store available).
func (m *mockDataStoreRegistry) DNS() datastores.DNSStore { return nil }

// System returns nil (no system store available).
func (m *mockDataStoreRegistry) System() datastores.SystemStore { return nil }

// Syscalls returns nil (no syscall store available).
func (m *mockDataStoreRegistry) Syscalls() datastores.SyscallStore { return nil }

// GetCustom always returns ErrNotFound.
func (m *mockDataStoreRegistry) GetCustom(name string) (datastores.DataStore, error) {
	return nil, datastores.ErrNotFound
}

// RegisterWritableStore always returns ErrNotFound (not supported in mock).
func (m *mockDataStoreRegistry) RegisterWritableStore(name string, store datastores.WritableStore) error {
	return datastores.ErrNotFound
}

// List returns an empty list.
func (m *mockDataStoreRegistry) List() []string { return nil }

// IsAvailable always returns false.
func (m *mockDataStoreRegistry) IsAvailable(name string) bool { return false }

// GetMetadata always returns ErrNotFound.
func (m *mockDataStoreRegistry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	return nil, datastores.ErrNotFound
}

// GetMetrics always returns ErrNotFound.
func (m *mockDataStoreRegistry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	return nil, datastores.ErrNotFound
}

// mockKernelSymbolStore implements KernelSymbolStore for testing.
// Provides configurable symbol resolution via the symbols map.
type mockKernelSymbolStore struct {
	symbols map[uint64][]*datastores.SymbolInfo
}

// Name returns the mock store identifier.
func (m *mockKernelSymbolStore) Name() string { return "mock_symbol" }

// GetHealth returns nil (no health info for mock).
func (m *mockKernelSymbolStore) GetHealth() *datastores.HealthInfo { return nil }

// GetMetrics returns nil (no metrics for mock).
func (m *mockKernelSymbolStore) GetMetrics() *datastores.DataStoreMetrics { return nil }

// ResolveSymbolByAddress returns symbols for the given address or ErrNotFound.
func (m *mockKernelSymbolStore) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	syms, ok := m.symbols[addr]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return syms, nil
}

// GetSymbolAddress always returns ErrNotFound (reverse lookup not implemented in mock).
func (m *mockKernelSymbolStore) GetSymbolAddress(name string) (uint64, error) {
	return 0, datastores.ErrNotFound
}

// ResolveSymbolsBatch always returns ErrNotImplemented.
func (m *mockKernelSymbolStore) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	return nil, datastores.ErrNotImplemented
}

// mockSyscallStore implements SyscallStore for testing.
// Provides configurable syscall ID/name mapping via the syscalls map.
type mockSyscallStore struct {
	syscalls map[int32]string
}

// Name returns the mock store identifier.
func (m *mockSyscallStore) Name() string { return "mock_syscall" }

// GetHealth returns nil (no health info for mock).
func (m *mockSyscallStore) GetHealth() *datastores.HealthInfo { return nil }

// GetMetrics returns nil (no metrics for mock).
func (m *mockSyscallStore) GetMetrics() *datastores.DataStoreMetrics { return nil }

// GetSyscallName returns the syscall name for the given ID or ErrNotFound.
func (m *mockSyscallStore) GetSyscallName(id int32) (string, error) {
	name, ok := m.syscalls[id]
	if !ok {
		return "", datastores.ErrNotFound
	}
	return name, nil
}

// GetSyscallID returns the syscall ID for the given name or ErrNotFound.
func (m *mockSyscallStore) GetSyscallID(name string) (int32, error) {
	for id, n := range m.syscalls {
		if n == name {
			return id, nil
		}
	}
	return 0, datastores.ErrNotFound
}

// mockDataStoreRegistryWithStores extends mockDataStoreRegistry for tests that need actual stores.
// Allows providing specific store implementations while keeping others as nil.
type mockDataStoreRegistryWithStores struct {
	mockDataStoreRegistry
	symbolStore  datastores.KernelSymbolStore
	syscallStore datastores.SyscallStore
}

// KernelSymbols returns the configured symbol store.
func (m *mockDataStoreRegistryWithStores) KernelSymbols() datastores.KernelSymbolStore {
	return m.symbolStore
}

// Syscalls returns the configured syscall store.
func (m *mockDataStoreRegistryWithStores) Syscalls() datastores.SyscallStore { return m.syscallStore }

// getOutputData extracts a string value from DetectorOutput.Data by field name
func getOutputData(output detection.DetectorOutput, name string) string {
	for _, ev := range output.Data {
		if ev.Name == name {
			if v, ok := ev.Value.(*v1beta1.EventValue_Str); ok {
				return v.Str
			}
		}
	}
	return ""
}
