package datastores

import "errors"

// Common errors for datastores
var (
	ErrNotFound        = errors.New("entity not found")
	ErrStoreUnhealthy  = errors.New("datastore is unhealthy")
	ErrNotImplemented  = errors.New("operation not implemented")
	ErrInvalidArgument = errors.New("invalid argument")
)

// StoreError wraps an error with additional context about the store
type StoreError struct {
	StoreName string
	Operation string
	Err       error
}

func (e *StoreError) Error() string {
	return e.StoreName + "." + e.Operation + ": " + e.Err.Error()
}

func (e *StoreError) Unwrap() error {
	return e.Err
}

// DataStore is the base interface for all datastores
type DataStore interface {
	// Name returns the name of this datastore
	Name() string

	// GetHealth returns the current health status of the datastore
	GetHealth() *HealthInfo

	// GetMetrics returns operational metrics for the datastore
	GetMetrics() *DataStoreMetrics
}

// ProcessStore provides access to process information
type ProcessStore interface {
	DataStore

	// GetProcess retrieves process information by entity ID
	// Returns ErrNotFound if the process is not found
	GetProcess(entityId uint32) (*ProcessInfo, error)

	// GetChildProcesses returns all child processes of the given process
	// Returns empty slice if no children found
	GetChildProcesses(entityId uint32) ([]*ProcessInfo, error)

	// GetAncestry retrieves the process ancestry chain up to maxDepth levels
	// Returns slice of ProcessInfo with [0] = process itself, [1] = parent, [2] = grandparent, etc.
	// If a parent is not found in the tree, the chain stops there
	// Returns empty slice if maxDepth <= 0 or process not found
	GetAncestry(entityId uint32, maxDepth int) ([]*ProcessInfo, error)
}

// ContainerStore provides access to container information
type ContainerStore interface {
	DataStore

	// GetContainer retrieves container information by container ID
	// Returns ErrNotFound if the container is not found
	GetContainer(id string) (*ContainerInfo, error)

	// GetContainerByName retrieves container information by container name
	// Returns ErrNotFound if no container with that name is found
	GetContainerByName(name string) (*ContainerInfo, error)
}

// KernelSymbolStore provides access to kernel symbol information
type KernelSymbolStore interface {
	DataStore

	// ResolveSymbolByAddress resolves a kernel address to symbol information
	// Returns multiple symbols if aliases exist at the same address
	// Returns ErrNotFound if the address cannot be resolved
	ResolveSymbolByAddress(addr uint64) ([]*SymbolInfo, error)

	// GetSymbolAddress returns the address of a named symbol
	// If multiple symbols exist with the same name (in different modules),
	// returns the address of the first one found.
	// Returns ErrNotFound if the symbol is not found
	GetSymbolAddress(name string) (uint64, error)

	// ResolveSymbolsBatch resolves multiple addresses to symbols in one call
	// Returns a map of address -> symbol info for found symbols
	// Missing addresses are not included in the result map
	ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*SymbolInfo, error)
}

// DNSStore provides access to cached DNS query responses
type DNSStore interface {
	DataStore

	// GetDNSResponse retrieves cached DNS response for a query
	// Returns ErrNotFound if no cached response is found
	GetDNSResponse(query string) (*DNSResponse, error)
}

// SystemStore provides access to immutable system information
type SystemStore interface {
	DataStore

	// GetSystemInfo returns complete system information collected at startup
	// This data is immutable and never changes during the Tracee process lifetime
	GetSystemInfo() *SystemInfo
}

// SyscallStore provides access to syscall metadata for the current architecture
type SyscallStore interface {
	DataStore

	// GetSyscallName returns the syscall name for a given ID
	// Returns ErrNotFound if the syscall ID is not found
	// Note: Syscall IDs are architecture-specific (x86 vs ARM)
	GetSyscallName(id int32) (string, error)

	// GetSyscallID returns the syscall ID for a given name
	// Returns ErrNotFound if the syscall name is not found
	// Note: Syscall IDs are architecture-specific (x86 vs ARM)
	GetSyscallID(name string) (int32, error)
}
