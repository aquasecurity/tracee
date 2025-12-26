package datastores

import (
	"errors"

	"google.golang.org/protobuf/types/known/anypb"
)

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

// WritableStore interface for datastores that support external data ingestion
// Stores implementing this interface can be written to by detectors, extensions,
// or external clients via gRPC.
//
// Ownership model: The entity that registers the store via Registry.RegisterWritableStore()
// owns the store and controls write access. Other consumers access via GetCustom[DataStore]()
// for read-only operations.
//
// DataEntry is defined in writable.proto and generated in writable.pb.go
type WritableStore interface {
	DataStore

	// WriteValue writes a single key-value entry from a source
	// The source parameter identifies the origin of the data (e.g., "crowdstrike_feed", "local_detector")
	// Returns error if the key/data types are invalid or the write fails
	WriteValue(source string, entry *DataEntry) error

	// WriteBatchValues writes multiple entries from a source in one operation
	// All entries are written atomically per-source (all succeed or all fail)
	// Returns error if any entry is invalid or the batch write fails
	WriteBatchValues(source string, entries []*DataEntry) error

	// Delete removes a specific key from a source
	// Returns error if the key type is invalid or the delete fails
	// Returns nil if the key doesn't exist (idempotent)
	Delete(source string, key *anypb.Any) error

	// ClearSource removes all data from a specific source
	// Returns error if the clear operation fails
	// Returns nil if the source doesn't exist (idempotent)
	ClearSource(source string) error

	// ListSources returns all source identifiers that have data in this store
	// Returns empty slice if no sources exist
	ListSources() ([]string, error)
}
