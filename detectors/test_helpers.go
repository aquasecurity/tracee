package detectors

import (
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

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
func (m *mockDataStoreRegistry) RegisterWritableStore(name string, store datastores.WritableStore) error {
	return nil // No-op for testing
}
func (m *mockDataStoreRegistry) List() []string               { return nil }
func (m *mockDataStoreRegistry) IsAvailable(name string) bool { return false }
func (m *mockDataStoreRegistry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	return nil, datastores.ErrNotFound
}
func (m *mockDataStoreRegistry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	return nil, datastores.ErrNotFound
}
