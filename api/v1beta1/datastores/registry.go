package datastores

// Registry provides unified access to all datastores
//
// IMPORTANT: All datastore accessor methods (Processes, Containers, etc.)
// always return a non-nil store instance, even if the store is unavailable
// or disabled. Use IsAvailable() or check store.GetHealth() to verify
// availability before use.
//
// Example checking availability:
//
//	registry := params.DataStores
//	if !registry.IsAvailable("process") {
//	    return errors.New("process store required but unavailable")
//	}
//	procStore := registry.Processes()  // Never nil
//	proc, err := procStore.GetProcess(entityId)
//	if errors.Is(err, ErrNotFound) {
//	    // Process not found
//	}
type Registry interface {
	// Processes returns the process datastore
	// Never returns nil - check IsAvailable("process") for availability
	Processes() ProcessStore

	// Containers returns the container datastore
	// Never returns nil - check IsAvailable("container") for availability
	Containers() ContainerStore

	// KernelSymbols returns the kernel symbol datastore
	// Never returns nil - check IsAvailable("symbol") for availability
	KernelSymbols() KernelSymbolStore

	// DNS returns the DNS cache datastore
	// Never returns nil - check IsAvailable("dns") for availability
	DNS() DNSStore

	// System returns the system information datastore
	// Never returns nil - check IsAvailable("system") for availability
	System() SystemStore

	// Syscalls returns the syscall information datastore
	// Never returns nil - check IsAvailable("syscall") for availability
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
