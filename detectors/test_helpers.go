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

// mockLogger for testing - implements detection.Logger
type mockLogger struct{}

func (m *mockLogger) Debugw(msg string, keysAndValues ...interface{}) {}
func (m *mockLogger) Infow(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Warnw(msg string, keysAndValues ...interface{})  {}
func (m *mockLogger) Errorw(msg string, keysAndValues ...interface{}) {}

// mockDataStoreRegistry for testing - implements datastores.Registry
type mockDataStoreRegistry struct{}

func (m *mockDataStoreRegistry) KernelSymbols() datastores.KernelSymbolStore { return nil }
func (m *mockDataStoreRegistry) Containers() datastores.ContainerStore       { return nil }
func (m *mockDataStoreRegistry) Processes() datastores.ProcessStore          { return nil }
func (m *mockDataStoreRegistry) DNS() datastores.DNSStore                    { return nil }
func (m *mockDataStoreRegistry) System() datastores.SystemStore              { return nil }
func (m *mockDataStoreRegistry) Syscalls() datastores.SyscallStore           { return nil }
func (m *mockDataStoreRegistry) GetCustom(name string) (datastores.DataStore, error) {
	return nil, datastores.ErrNotFound
}
func (m *mockDataStoreRegistry) List() []string               { return nil }
func (m *mockDataStoreRegistry) IsAvailable(name string) bool { return false }
func (m *mockDataStoreRegistry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	return nil, datastores.ErrNotFound
}
func (m *mockDataStoreRegistry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	return nil, datastores.ErrNotFound
}

// mockKernelSymbolStore implements KernelSymbolStore for testing
type mockKernelSymbolStore struct {
	symbols map[uint64][]*datastores.SymbolInfo
}

func (m *mockKernelSymbolStore) Name() string                             { return "mock_symbol" }
func (m *mockKernelSymbolStore) GetHealth() *datastores.HealthInfo        { return nil }
func (m *mockKernelSymbolStore) GetMetrics() *datastores.DataStoreMetrics { return nil }
func (m *mockKernelSymbolStore) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	syms, ok := m.symbols[addr]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return syms, nil
}
func (m *mockKernelSymbolStore) GetSymbolAddress(name string) (uint64, error) {
	return 0, datastores.ErrNotFound
}
func (m *mockKernelSymbolStore) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	return nil, datastores.ErrNotImplemented
}

// mockSyscallStore implements SyscallStore for testing
type mockSyscallStore struct {
	syscalls map[int32]string
}

func (m *mockSyscallStore) Name() string                             { return "mock_syscall" }
func (m *mockSyscallStore) GetHealth() *datastores.HealthInfo        { return nil }
func (m *mockSyscallStore) GetMetrics() *datastores.DataStoreMetrics { return nil }
func (m *mockSyscallStore) GetSyscallName(id int32) (string, error) {
	name, ok := m.syscalls[id]
	if !ok {
		return "", datastores.ErrNotFound
	}
	return name, nil
}
func (m *mockSyscallStore) GetSyscallID(name string) (int32, error) {
	for id, n := range m.syscalls {
		if n == name {
			return id, nil
		}
	}
	return 0, datastores.ErrNotFound
}

// mockDataStoreRegistryWithStores extends mockDataStoreRegistry for tests that need actual stores
type mockDataStoreRegistryWithStores struct {
	mockDataStoreRegistry
	symbolStore  datastores.KernelSymbolStore
	syscallStore datastores.SyscallStore
}

func (m *mockDataStoreRegistryWithStores) KernelSymbols() datastores.KernelSymbolStore {
	return m.symbolStore
}
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
