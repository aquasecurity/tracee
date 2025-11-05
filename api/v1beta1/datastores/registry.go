package datastores

// Registry provides unified access to all datastores
type Registry interface {
	// Processes returns the process datastore
	Processes() ProcessStore

	// Containers returns the container datastore
	Containers() ContainerStore

	// KernelSymbols returns the kernel symbol datastore
	KernelSymbols() KernelSymbolStore

	// DNS returns the DNS cache datastore
	DNS() DNSStore

	// System returns the system information datastore
	System() SystemStore

	// Syscalls returns the syscall information datastore
	Syscalls() SyscallStore

	// GetCustom retrieves a custom datastore by name
	// Returns ErrNotFound if the datastore is not registered
	GetCustom(name string) (DataStore, error)

	// List returns names of all registered datastores
	List() []string

	// IsAvailable checks if a datastore with the given name is available
	IsAvailable(name string) bool

	// GetMetadata returns metadata about a specific datastore
	// Returns ErrNotFound if the datastore is not registered
	GetMetadata(name string) (*DataStoreMetadata, error)

	// GetMetrics returns metrics for a specific datastore
	// Returns ErrNotFound if the datastore is not registered
	GetMetrics(name string) (*DataStoreMetrics, error)
}
