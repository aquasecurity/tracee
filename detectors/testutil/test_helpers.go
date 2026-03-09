package testutil

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
//   - MockLogger: Minimal logger that discards all output
//   - MockDataStoreRegistry: Returns nil for all datastore types
//
// Functional Mocks (configurable test doubles):
//   - MockKernelSymbolStore: Symbol resolution with configurable symbol map
//   - MockSyscallStore: Syscall ID/name mapping with configurable syscall map
//   - MockDataStoreRegistryWithStores: Registry that provides specific store implementations
//
// Helper Functions:
//   - GetOutputData: Extracts string values from DetectorOutput for test assertions
//
// Usage:
//   - Use basic mocks (MockLogger, MockDataStoreRegistry) for detectors that don't need datastore access
//   - Use functional mocks (MockKernelSymbolStore, MockSyscallStore) for detectors requiring symbol/syscall lookups
//   - Implement custom mocks for detectors with complex datastore requirements

// MockLogger for testing - implements detection.Logger.
// All logging methods are no-ops, discarding output for test clarity.
type MockLogger struct{}

// Debugw discards debug log messages.
func (m *MockLogger) Debugw(msg string, keysAndValues ...interface{}) {}

// Infow discards info log messages.
func (m *MockLogger) Infow(msg string, keysAndValues ...interface{}) {}

// Warnw discards warning log messages.
func (m *MockLogger) Warnw(msg string, keysAndValues ...interface{}) {}

// Errorw discards error log messages.
func (m *MockLogger) Errorw(msg string, keysAndValues ...interface{}) {}

// MockDataStoreRegistry for testing - implements datastores.Registry.
// All methods return nil or empty values, suitable for tests where datastores aren't needed.
type MockDataStoreRegistry struct{}

// KernelSymbols returns nil (no symbol store available).
func (m *MockDataStoreRegistry) KernelSymbols() datastores.KernelSymbolStore { return nil }

// Containers returns nil (no container store available).
func (m *MockDataStoreRegistry) Containers() datastores.ContainerStore { return nil }

// Processes returns nil (no process store available).
func (m *MockDataStoreRegistry) Processes() datastores.ProcessStore { return nil }

// DNS returns nil (no DNS store available).
func (m *MockDataStoreRegistry) DNS() datastores.DNSStore { return nil }

// System returns nil (no system store available).
func (m *MockDataStoreRegistry) System() datastores.SystemStore { return nil }

// Syscalls returns nil (no syscall store available).
func (m *MockDataStoreRegistry) Syscalls() datastores.SyscallStore { return nil }

// GetCustom always returns ErrNotFound.
func (m *MockDataStoreRegistry) GetCustom(name string) (datastores.DataStore, error) {
	return nil, datastores.ErrNotFound
}

// RegisterWritableStore always returns ErrNotFound (not supported in mock).
func (m *MockDataStoreRegistry) RegisterWritableStore(name string, store datastores.WritableStore) error {
	return datastores.ErrNotFound
}

// List returns an empty list.
func (m *MockDataStoreRegistry) List() []string { return nil }

// IsAvailable always returns false.
func (m *MockDataStoreRegistry) IsAvailable(name string) bool { return false }

// GetMetadata always returns ErrNotFound.
func (m *MockDataStoreRegistry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	return nil, datastores.ErrNotFound
}

// GetMetrics always returns ErrNotFound.
func (m *MockDataStoreRegistry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	return nil, datastores.ErrNotFound
}

// MockKernelSymbolStore implements KernelSymbolStore for testing.
// Provides configurable symbol resolution via the Symbols map.
type MockKernelSymbolStore struct {
	Symbols map[uint64][]*datastores.SymbolInfo
}

// Name returns the mock store identifier.
func (m *MockKernelSymbolStore) Name() string { return "mock_symbol" }

// GetHealth returns nil (no health info for mock).
func (m *MockKernelSymbolStore) GetHealth() *datastores.HealthInfo { return nil }

// GetMetrics returns nil (no metrics for mock).
func (m *MockKernelSymbolStore) GetMetrics() *datastores.DataStoreMetrics { return nil }

// ResolveSymbolByAddress returns symbols for the given address or ErrNotFound.
func (m *MockKernelSymbolStore) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	syms, ok := m.Symbols[addr]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return syms, nil
}

// GetSymbolAddress always returns ErrNotFound (reverse lookup not implemented in mock).
func (m *MockKernelSymbolStore) GetSymbolAddress(name string) (uint64, error) {
	return 0, datastores.ErrNotFound
}

// ResolveSymbolsBatch always returns ErrNotImplemented.
func (m *MockKernelSymbolStore) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	return nil, datastores.ErrNotImplemented
}

// MockSyscallStore implements SyscallStore for testing.
// Provides configurable syscall ID/name mapping via the Syscalls map.
type MockSyscallStore struct {
	Syscalls map[int32]string
}

// Name returns the mock store identifier.
func (m *MockSyscallStore) Name() string { return "mock_syscall" }

// GetHealth returns nil (no health info for mock).
func (m *MockSyscallStore) GetHealth() *datastores.HealthInfo { return nil }

// GetMetrics returns nil (no metrics for mock).
func (m *MockSyscallStore) GetMetrics() *datastores.DataStoreMetrics { return nil }

// GetSyscallName returns the syscall name for the given ID or ErrNotFound.
func (m *MockSyscallStore) GetSyscallName(id int32) (string, error) {
	name, ok := m.Syscalls[id]
	if !ok {
		return "", datastores.ErrNotFound
	}
	return name, nil
}

// GetSyscallID returns the syscall ID for the given name or ErrNotFound.
func (m *MockSyscallStore) GetSyscallID(name string) (int32, error) {
	for id, n := range m.Syscalls {
		if n == name {
			return id, nil
		}
	}
	return 0, datastores.ErrNotFound
}

// MockDataStoreRegistryWithStores extends MockDataStoreRegistry for tests that need actual stores.
// Allows providing specific store implementations while keeping others as nil.
type MockDataStoreRegistryWithStores struct {
	MockDataStoreRegistry
	SymbolStore  datastores.KernelSymbolStore
	SyscallStore datastores.SyscallStore
}

// KernelSymbols returns the configured symbol store.
func (m *MockDataStoreRegistryWithStores) KernelSymbols() datastores.KernelSymbolStore {
	return m.SymbolStore
}

// Syscalls returns the configured syscall store.
func (m *MockDataStoreRegistryWithStores) Syscalls() datastores.SyscallStore { return m.SyscallStore }

// GetOutputData extracts a string value from DetectorOutput.Data by field name
func GetOutputData(output detection.DetectorOutput, name string) string {
	for _, ev := range output.Data {
		if ev.Name == name {
			if v, ok := ev.Value.(*v1beta1.EventValue_Str); ok {
				return v.Str
			}
		}
	}
	return ""
}
