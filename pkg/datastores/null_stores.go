package datastores

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// Null object implementations for datastores
// These are returned when a store is not registered, ensuring accessor methods never return nil

// nullProcessStore implements ProcessStore with all operations returning ErrStoreUnhealthy
type nullProcessStore struct{}

func (n *nullProcessStore) Name() string { return "null_process" }

func (n *nullProcessStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "process store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullProcessStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullProcessStore) GetProcess(entityId uint32) (*datastores.ProcessInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

func (n *nullProcessStore) GetChildProcesses(entityId uint32) ([]*datastores.ProcessInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

func (n *nullProcessStore) GetAncestry(entityId uint32, maxDepth int) ([]*datastores.ProcessInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

// nullContainerStore implements ContainerStore with all operations returning ErrStoreUnhealthy
type nullContainerStore struct{}

func (n *nullContainerStore) Name() string { return "null_container" }

func (n *nullContainerStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "container store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullContainerStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullContainerStore) GetContainer(id string) (*datastores.ContainerInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

func (n *nullContainerStore) GetContainerByName(name string) (*datastores.ContainerInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

// nullKernelSymbolStore implements KernelSymbolStore with all operations returning ErrStoreUnhealthy
type nullKernelSymbolStore struct{}

func (n *nullKernelSymbolStore) Name() string { return "null_symbol" }

func (n *nullKernelSymbolStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "kernel symbol store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullKernelSymbolStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullKernelSymbolStore) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

func (n *nullKernelSymbolStore) GetSymbolAddress(name string) (uint64, error) {
	return 0, datastores.ErrStoreUnhealthy
}

func (n *nullKernelSymbolStore) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	return nil, datastores.ErrStoreUnhealthy
}

// nullDNSStore implements DNSStore with all operations returning ErrStoreUnhealthy
type nullDNSStore struct{}

func (n *nullDNSStore) Name() string { return "null_dns" }

func (n *nullDNSStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "DNS store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullDNSStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullDNSStore) GetDNSResponse(query string) (*datastores.DNSResponse, error) {
	return nil, datastores.ErrStoreUnhealthy
}

// nullSystemStore implements SystemStore with all operations returning ErrStoreUnhealthy
type nullSystemStore struct{}

func (n *nullSystemStore) Name() string { return "null_system" }

func (n *nullSystemStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "system store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullSystemStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullSystemStore) GetSystemInfo() *datastores.SystemInfo {
	return &datastores.SystemInfo{}
}

// nullSyscallStore implements SyscallStore with all operations returning ErrStoreUnhealthy
type nullSyscallStore struct{}

func (n *nullSyscallStore) Name() string { return "null_syscall" }

func (n *nullSyscallStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "syscall store not available",
		LastCheck: time.Now(),
	}
}

func (n *nullSyscallStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:  0,
		LastAccess: time.Now(),
	}
}

func (n *nullSyscallStore) GetSyscallName(id int32) (string, error) {
	return "", datastores.ErrStoreUnhealthy
}

func (n *nullSyscallStore) GetSyscallID(name string) (int32, error) {
	return 0, datastores.ErrStoreUnhealthy
}
